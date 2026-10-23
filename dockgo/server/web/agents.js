/* Agents page: remote Docker host registration and management. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("agents-table-body");
    const emptyEl = document.getElementById("agents-empty");
    const statusEl = document.getElementById("agents-status");
    const refreshListBtn = document.getElementById("refresh-agents-list-btn");
    const addAgentBtn = document.getElementById("add-agent-btn");
    const registeredStatEl = document.getElementById("agents-stat-registered");
    const onlineStatEl = document.getElementById("agents-stat-online");
    const hostSelector = document.getElementById("host-selector");

    const agentModal = document.getElementById("agent-modal");
    const agentForm = document.getElementById("agent-form");
    const agentNameInput = document.getElementById("agent-name");
    const agentFormError = document.getElementById("agent-form-error");
    const closeAgentBtn = document.getElementById("close-agent-btn");
    const agentCancelBtn = document.getElementById("agent-cancel-btn");

    const agentKeyModal = document.getElementById("agent-key-modal");
    const agentKeyValue = document.getElementById("agent-key-value");
    const agentKeyCopyBtn = document.getElementById("agent-key-copy-btn");
    const agentKeyCloseBtn = document.getElementById("agent-key-close-btn");
    const closeAgentKeyBtn = document.getElementById("close-agent-key-btn");

    const page = window.DockGoPage;

    let rows = [];
    let pager;

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

    const showStatus = (message, tone = "error") => {
        if (!statusEl) return;
        const colors = {
            success: "var(--success)",
            info: "var(--text-secondary)",
        };
        statusEl.textContent = message;
        statusEl.style.color = colors[tone] || "";
        statusEl.classList.toggle("success", tone === "success");
        statusEl.classList.toggle("info", tone === "info");
        statusEl.classList.remove("hidden");
    };

    const hideStatus = () => {
        if (!statusEl) return;
        statusEl.classList.add("hidden");
        statusEl.classList.remove("success", "info");
        statusEl.style.color = "";
    };

    const setBusy = (busy) => {
        [refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
        });
    };

    const statusClass = (status) => {
        switch (status) {
            case "online":
                return "status-online";
            case "disabled":
                return "status-warning";
            default:
                return "status-other";
        }
    };

    const agentSortValue = (agent, key) => {
        switch (key) {
            case "name":
                return (agent.name || "").toLowerCase();
            case "hostname":
                return (agent.hostname || "").toLowerCase();
            case "status":
                return (agent.status || "").toLowerCase();
            case "version":
                return (agent.version || "").toLowerCase();
            case "last_seen":
                return Date.parse(agent.last_seen) || 0;
            default:
                return "";
        }
    };

    const formatLastSeen = (value) => {
        if (!value || String(value).startsWith("0001-01-01")) return "Never";
        return page.formatDate(value);
    };

    const makeActionButton = ({ icon, label, danger = false }) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `stack-row-action${danger ? " danger" : ""}`;
        button.title = label;
        button.setAttribute("aria-label", label);
        button.innerHTML = `<span class="nf ${icon}" aria-hidden="true"></span>`;
        return button;
    };

    const renderAgents = () => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (rows.length === 0) {
            emptyEl.textContent =
                'No agents registered yet. Click "Add Agent" to create one.';
            emptyEl.classList.remove("hidden");
            if (pager) pager.render(0);
            return;
        }
        emptyEl.classList.add("hidden");

        const sorted = sorter.sort(rows, agentSortValue);
        if (pager) pager.render(sorted.length);
        const visible = pager ? pager.slice(sorted) : sorted;

        visible.forEach((agent) => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const name = document.createElement("span");
            name.className = "cell-name";
            name.textContent = agent.name || "-";
            nameCell.appendChild(name);

            const hostnameCell = document.createElement("td");
            hostnameCell.className = "cell-name";
            hostnameCell.textContent = agent.hostname || "-";

            const statusCell = document.createElement("td");
            const statusBadge = document.createElement("span");
            statusBadge.className = `status-badge ${statusClass(agent.status)}`;
            statusBadge.textContent = agent.status || "offline";
            statusCell.appendChild(statusBadge);

            const versionCell = document.createElement("td");
            versionCell.className = "cell-data";
            versionCell.textContent = agent.version || "unknown";

            const lastSeenCell = document.createElement("td");
            lastSeenCell.className = "cell-data";
            lastSeenCell.textContent = formatLastSeen(agent.last_seen);

            const rotateBtn = makeActionButton({
                icon: "nf-refresh",
                label: `Rotate key for ${agent.name}`,
            });
            const deleteBtn = makeActionButton({
                icon: "nf-trash",
                label: `Delete ${agent.name}`,
                danger: true,
            });
            const actionButtons = [rotateBtn, deleteBtn];
            rotateBtn.addEventListener("click", () =>
                rotateAgentKey(agent, actionButtons),
            );
            deleteBtn.addEventListener("click", () =>
                deleteAgent(agent, actionButtons),
            );

            const actionsCell = document.createElement("td");
            actionsCell.className = "actions-cell";
            const actionsWrap = document.createElement("div");
            actionsWrap.className = "stack-row-actions";
            actionsWrap.append(rotateBtn, deleteBtn);
            actionsCell.appendChild(actionsWrap);

            row.append(
                nameCell,
                hostnameCell,
                statusCell,
                versionCell,
                lastSeenCell,
                actionsCell,
            );
            tableBodyEl.appendChild(row);
        });
    };

    const sorter = page.createTableSorter(
        () => {
            if (pager) pager.reset();
            renderAgents();
        },
        { key: "name" },
    );

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".agents-table",
            storageKey: "dockgo_columns_agents",
        });
    }

    if (page && page.createPager) {
        pager = page.createPager({
            tableSelector: ".agents-table",
            onChange: renderAgents,
        });
    }

    const updateStats = (agents) => {
        if (registeredStatEl) {
            registeredStatEl.textContent = String(agents.length);
        }
        if (onlineStatEl) {
            onlineStatEl.textContent = String(
                agents.filter((agent) => agent.status === "online").length,
            );
        }
    };

    const fetchAgents = async ({ showLoading = false, busy = false } = {}) => {
        if (!page) return false;
        if (busy) setBusy(true);
        if (showLoading && emptyEl) {
            emptyEl.textContent = "Loading agents...";
            emptyEl.classList.remove("hidden");
        }

        try {
            const response = await fetch("/api/agents", {
                headers: page.getAuthHeaders(),
            });

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                showStatus("Authentication required to list agents.");
                if (showLoading && emptyEl) {
                    emptyEl.textContent = "Authentication required.";
                    emptyEl.classList.remove("hidden");
                }
                return false;
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            const data = await response.json();
            rows = data && Array.isArray(data.agents) ? data.agents : [];
            updateStats(rows);
            renderAgents();
            return true;
        } catch (error) {
            console.error("Failed to fetch agents", error);
            showStatus(`Failed to load agents: ${error.message}`);
            if (showLoading && emptyEl) {
                emptyEl.textContent = "Failed to load agents.";
                emptyEl.classList.remove("hidden");
            }
            return false;
        } finally {
            if (busy) setBusy(false);
        }
    };

    const showAgentKey = (key) => {
        if (agentKeyValue) agentKeyValue.textContent = key;
        if (agentKeyCopyBtn) agentKeyCopyBtn.textContent = "Copy Key";
        if (agentKeyModal) agentKeyModal.classList.remove("hidden");
    };

    const hideAgentKey = () => {
        if (agentKeyModal) agentKeyModal.classList.add("hidden");
        if (agentKeyValue) agentKeyValue.textContent = "";
        if (agentKeyCopyBtn) agentKeyCopyBtn.textContent = "Copy Key";
    };

    const openAgentModal = () => {
        if (!agentModal) return;
        if (agentForm) agentForm.reset();
        if (agentFormError) agentFormError.classList.add("hidden");
        agentModal.classList.remove("hidden");
        if (agentNameInput) agentNameInput.focus();
    };

    const closeAgentModal = () => {
        if (agentModal) agentModal.classList.add("hidden");
    };

    const rotateAgentKey = async (agent, buttons = []) => {
        const confirmed = await page.showConfirmModal({
            title: "Rotate Agent Key",
            message: `Rotate the key for "${agent.name}"? The current key will stop working.`,
            confirmLabel: "Rotate Key",
            danger: true,
        });
        if (!confirmed) return;

        buttons.forEach((button) => {
            if (button) button.disabled = true;
        });
        hideStatus();
        showStatus(`Rotating key for ${agent.name}...`, "info");

        try {
            const response = await fetch(
                `/api/agents/${encodeURIComponent(agent.id)}/rotate-key`,
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

            const data = await response.json();
            showAgentKey(data.key);
            showStatus(`Key rotated for ${agent.name}.`, "success");
            await fetchAgents();
            if (page.refreshAgents) await page.refreshAgents();
        } catch (error) {
            console.error("Failed to rotate agent key", error);
            showStatus(`Rotate key failed: ${error.message}`);
        } finally {
            buttons.forEach((button) => {
                if (button) button.disabled = false;
            });
        }
    };

    const deleteAgent = async (agent, buttons = []) => {
        const confirmed = await page.showConfirmModal({
            title: "Delete Agent",
            message: `Delete agent "${agent.name}"? This disconnects it permanently.`,
            confirmLabel: "Delete",
            danger: true,
        });
        if (!confirmed) return;

        buttons.forEach((button) => {
            if (button) button.disabled = true;
        });
        hideStatus();
        showStatus(`Deleting ${agent.name}...`, "info");

        try {
            const response = await fetch(
                `/api/agents/${encodeURIComponent(agent.id)}`,
                {
                    method: "DELETE",
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

            if (
                hostSelector &&
                page.getState().currentAgentID === agent.id
            ) {
                hostSelector.value = "";
                hostSelector.dispatchEvent(new Event("change"));
            }

            showStatus(`Deleted agent ${agent.name}.`, "success");
            await fetchAgents();
            if (page.refreshAgents) await page.refreshAgents();
        } catch (error) {
            console.error("Failed to delete agent", error);
            showStatus(`Delete failed: ${error.message}`);
        } finally {
            buttons.forEach((button) => {
                if (button) button.disabled = false;
            });
        }
    };

    if (refreshListBtn) {
        refreshListBtn.addEventListener("click", () =>
            fetchAgents({ busy: true }),
        );
    }
    if (addAgentBtn) addAgentBtn.addEventListener("click", openAgentModal);
    if (closeAgentBtn) closeAgentBtn.addEventListener("click", closeAgentModal);
    if (agentCancelBtn) {
        agentCancelBtn.addEventListener("click", closeAgentModal);
    }
    if (agentModal) {
        agentModal.addEventListener("click", (event) => {
            if (event.target === agentModal) closeAgentModal();
        });
    }

    if (agentForm) {
        agentForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            if (agentFormError) agentFormError.classList.add("hidden");
            const name = agentNameInput ? agentNameInput.value.trim() : "";
            if (!name) return;

            try {
                const response = await fetch("/api/agents", {
                    method: "POST",
                    headers: page.getAuthHeaders(true),
                    body: JSON.stringify({ name }),
                });
                if (!response.ok) {
                    throw new Error(await responseErrorMessage(response));
                }
                const data = await response.json();
                closeAgentModal();
                showAgentKey(data.key);
                showStatus(`Created agent ${name}.`, "success");
                await fetchAgents();
                if (page.refreshAgents) await page.refreshAgents();
            } catch (error) {
                console.error("Failed to create agent", error);
                if (agentFormError) {
                    agentFormError.textContent = error.message;
                    agentFormError.classList.remove("hidden");
                }
            }
        });
    }

    if (agentKeyCloseBtn) {
        agentKeyCloseBtn.addEventListener("click", hideAgentKey);
    }
    if (closeAgentKeyBtn) {
        closeAgentKeyBtn.addEventListener("click", hideAgentKey);
    }
    if (agentKeyModal) {
        agentKeyModal.addEventListener("click", (event) => {
            if (event.target === agentKeyModal) hideAgentKey();
        });
    }
    if (agentKeyCopyBtn) {
        agentKeyCopyBtn.addEventListener("click", async () => {
            const key = agentKeyValue ? agentKeyValue.textContent : "";
            if (!key) return;
            try {
                await navigator.clipboard.writeText(key);
                agentKeyCopyBtn.textContent = "Copied!";
            } catch (error) {
                console.error("Failed to copy agent key", error);
                agentKeyCopyBtn.textContent = "Copy failed";
            }
            window.setTimeout(() => {
                agentKeyCopyBtn.textContent = "Copy Key";
            }, 2000);
        });
    }

    window.setInterval(() => {
        const agentModalOpen =
            agentModal && !agentModal.classList.contains("hidden");
        const keyModalOpen =
            agentKeyModal && !agentKeyModal.classList.contains("hidden");
        if (!document.hidden && !agentModalOpen && !keyModalOpen) {
            fetchAgents();
        }
    }, 15000);

    if (page) {
        page.init({
            onReady: () => fetchAgents({ showLoading: true }),
            onLogin: () => fetchAgents({ showLoading: true }),
            onHostChange: () => fetchAgents(),
        });
    }
});

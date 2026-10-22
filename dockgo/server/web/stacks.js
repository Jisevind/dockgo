/* Stacks page: registered stacks with aggregated live usage. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("stacks-table-body");
    const emptyEl = document.getElementById("stacks-empty");
    const statusEl = document.getElementById("stacks-status");
    const refreshBtn = document.getElementById("refresh-stacks-btn");
    const refreshListBtn = document.getElementById("refresh-stacks-list-btn");

    const page = window.DockGoPage;

    let rows = [];
    let pager;
    const expanded = new Set();

    const stateStatusClass = (state) => {
        switch (state) {
            case "running":
                return "status-running";
            case "exited":
            case "dead":
            case "stopped":
                return "status-exited";
            default:
                return "status-other";
        }
    };

    const stackSortValue = (stack, key) => {
        switch (key) {
            case "name":
                return (stack.name || "").toLowerCase();
            case "status":
                return (stack.status || "").toLowerCase();
            case "ownership":
                return (stack.ownership || "").toLowerCase();
            case "source":
                return (stack.source || "").toLowerCase();
            case "location":
                return (stack.location || "").toLowerCase();
            case "containers":
                return stack.containers || 0;
            case "cpu":
                return stack.cpu_percent || 0;
            case "memory":
                return stack.memory_used || 0;
            case "net":
                return (stack.net_rx || 0) + (stack.net_tx || 0);
            case "disk":
                return (stack.disk_read || 0) + (stack.disk_write || 0);
            case "networks":
                return stack.networks || 0;
            case "volumes":
                return stack.volumes || 0;
            default:
                return "";
        }
    };

    const stateBadge = (state) => {
        const normalized = state || "unknown";
        const badge = document.createElement("span");
        badge.className = `status-badge ${stateStatusClass(normalized)}`;
        badge.textContent = normalized;
        return badge;
    };

    const ownershipStatusClass = (ownership) => {
        switch (ownership) {
            case "bound":
                return "status-running";
            case "drifted":
                return "status-warning";
            case "unbound":
                return "status-other";
            default:
                return "status-other";
        }
    };

    const ownershipBadge = (ownership) => {
        const normalized = ownership || "unknown";
        const descriptions = {
            bound: "Managed containers match runtime ownership.",
            drifted: "Runtime containers do not match recorded ownership.",
            unbound: "No managed containers recorded yet.",
        };
        const badge = document.createElement("span");
        badge.className = `status-badge ${ownershipStatusClass(normalized)}`;
        badge.textContent = normalized;
        badge.title = descriptions[normalized] || "";
        return badge;
    };

    const memberTable = (members) => {
        const table = document.createElement("table");
        table.className = "stack-containers-table";

        const head = document.createElement("thead");
        const headRow = document.createElement("tr");
        ["Container", "State", "Image", "CPU", "Memory"].forEach((label) => {
            const th = document.createElement("th");
            th.textContent = label;
            headRow.appendChild(th);
        });
        head.appendChild(headRow);
        table.appendChild(head);

        const body = document.createElement("tbody");
        members.forEach((member) => {
            const tr = document.createElement("tr");

            const nameCell = document.createElement("td");
            const name = document.createElement("span");
            name.className = "container-table-name";
            name.textContent = member.name || "-";
            nameCell.appendChild(name);

            const stateCell = document.createElement("td");
            const stateWrap = document.createElement("div");
            stateWrap.className = "state-cell";
            stateWrap.appendChild(stateBadge(member.state));
            stateWrap.appendChild(
                page.createContainerActionButton({
                    name: member.name,
                    state: member.state,
                    onDone: () => window.setTimeout(fetchStacks, 800),
                    onError: (message) => showStatus(message),
                }),
            );
            stateCell.appendChild(stateWrap);

            const imageCell = document.createElement("td");
            const image = document.createElement("span");
            image.className = "container-table-image";
            image.textContent = member.image || "-";
            imageCell.appendChild(image);

            const cpuCell = document.createElement("td");
            cpuCell.className = "cell-data";
            cpuCell.textContent =
                member.state === "running"
                    ? `${(member.cpu_percent || 0).toFixed(1)}%`
                    : "-";

            const memoryCell = document.createElement("td");
            memoryCell.className = "cell-data";
            if (member.state === "running" && member.memory_limit) {
                memoryCell.textContent = `${page.formatBytesCompact(member.memory_used)}/${page.formatBytesCompact(member.memory_limit)}`;
            } else {
                memoryCell.textContent = "-";
            }

            tr.append(nameCell, stateCell, imageCell, cpuCell, memoryCell);
            body.appendChild(tr);
        });
        table.appendChild(body);
        return table;
    };

    const renderRows = () => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (rows.length === 0) {
            emptyEl.textContent =
                "No registered stacks. Register stacks from the dashboard Stacks tab.";
            emptyEl.classList.remove("hidden");
            if (pager) pager.render(0);
            return;
        }
        emptyEl.classList.add("hidden");

        const sorted = sorter.sort(rows, stackSortValue);
        if (pager) pager.render(sorted.length);
        const visible = pager ? pager.slice(sorted) : sorted;

        visible.forEach((stack) => {
            const isExpanded = expanded.has(stack.id);
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const nameWrap = document.createElement("div");
            nameWrap.className = "stack-name-cell";

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = `expand-btn${isExpanded ? " expanded" : ""}`;
            toggle.setAttribute(
                "aria-expanded",
                isExpanded ? "true" : "false",
            );
            toggle.setAttribute(
                "aria-label",
                `${isExpanded ? "Collapse" : "Expand"} ${stack.name}`,
            );
            toggle.textContent = "›";
            toggle.addEventListener("click", () => {
                if (expanded.has(stack.id)) {
                    expanded.delete(stack.id);
                } else {
                    expanded.add(stack.id);
                }
                renderRows();
            });

            const name = document.createElement("span");
            name.className = "stack-table-name";
            name.textContent = stack.name || "-";

            nameWrap.append(toggle, name);
            nameCell.appendChild(nameWrap);

            const statusCell = document.createElement("td");
            statusCell.appendChild(stateBadge(stack.status));

            const ownershipCell = document.createElement("td");
            ownershipCell.appendChild(ownershipBadge(stack.ownership));

            const sourceCell = document.createElement("td");
            const source = document.createElement("span");
            source.className = "source-tag";
            source.textContent = stack.source || "Unknown";
            sourceCell.appendChild(source);

            const locationCell = document.createElement("td");
            const location = document.createElement("span");
            location.className = "cell-name";
            location.textContent = stack.location || "Not set";
            location.title = stack.location || "";
            locationCell.appendChild(location);

            const containersCell = document.createElement("td");
            containersCell.className = "cell-data";
            if ((stack.running || 0) > 0) {
                const running = document.createElement("span");
                running.className = "running-count";
                running.textContent = `▶${stack.running}`;
                containersCell.appendChild(running);
            }
            if ((stack.stopped || 0) > 0) {
                const stopped = document.createElement("span");
                stopped.className = "stopped-count";
                stopped.textContent = `□${stack.stopped}`;
                containersCell.appendChild(stopped);
            }
            if (!containersCell.textContent) {
                containersCell.textContent = "-";
            }

            const cpuCell = document.createElement("td");
            cpuCell.className = "cell-data";
            cpuCell.textContent =
                stack.running > 0
                    ? `${(stack.cpu_percent || 0).toFixed(1)}%`
                    : "-";

            const memoryCell = document.createElement("td");
            memoryCell.className = "cell-data";
            if (stack.running > 0 && stack.memory_limit) {
                const memory = document.createElement("span");
                memory.textContent = `${page.formatBytesCompact(stack.memory_used)}/${page.formatBytesCompact(stack.memory_limit)}`;
                if (stack.memory_used / stack.memory_limit >= 0.75) {
                    memory.className = "memory-warning";
                }
                memoryCell.appendChild(memory);
            } else {
                memoryCell.textContent = "-";
            }

            const netCell = document.createElement("td");
            netCell.className = "cell-data";
            netCell.textContent =
                stack.running > 0
                    ? `↓${page.formatBytesCompact(stack.net_rx)} ↑${page.formatBytesCompact(stack.net_tx)}`
                    : "-";

            const diskCell = document.createElement("td");
            diskCell.className = "cell-data";
            diskCell.textContent =
                stack.running > 0
                    ? `r${page.formatBytesCompact(stack.disk_read)} w${page.formatBytesCompact(stack.disk_write)}`
                    : "-";

            const networksCell = document.createElement("td");
            networksCell.className = "cell-data";
            networksCell.textContent = stack.networks ? String(stack.networks) : "-";

            const volumesCell = document.createElement("td");
            volumesCell.className = "cell-data";
            volumesCell.textContent = stack.volumes ? String(stack.volumes) : "-";

            row.append(
                nameCell,
                statusCell,
                ownershipCell,
                sourceCell,
                locationCell,
                containersCell,
                cpuCell,
                memoryCell,
                netCell,
                diskCell,
                networksCell,
                volumesCell,
            );
            tableBodyEl.appendChild(row);

            if (isExpanded) {
                const detailRow = document.createElement("tr");
                detailRow.className = "stack-detail-row";
                detailRow.dataset.detailRow = "true";
                const detailCell = document.createElement("td");
                detailCell.colSpan = 12;

                const toolbar = document.createElement("div");
                toolbar.className = "stack-detail-toolbar";
                const editLink = document.createElement("a");
                editLink.className = "btn secondary small";
                const agentID = page.getState().currentAgentID;
                editLink.href =
                    `/stacks/${encodeURIComponent(stack.id)}/files` +
                    (agentID
                        ? `?agent=${encodeURIComponent(agentID)}`
                        : "");
                editLink.innerHTML =
                    '<span class="nf nf-file-edit" aria-hidden="true"></span>Edit Files';
                toolbar.appendChild(editLink);

                const reconcileBtn = document.createElement("button");
                reconcileBtn.type = "button";
                reconcileBtn.className = "btn secondary small";
                reconcileBtn.innerHTML =
                    '<span class="nf nf-sync" aria-hidden="true"></span>Reconcile';
                reconcileBtn.title =
                    "Reconcile stack ownership with runtime containers";
                if (stack.ownership === "bound") {
                    reconcileBtn.disabled = true;
                    reconcileBtn.title = "Ownership is already bound";
                }

                const deployBtn = document.createElement("button");
                deployBtn.type = "button";
                deployBtn.className = "btn primary small";
                deployBtn.innerHTML =
                    '<span class="nf nf-rocket" aria-hidden="true"></span>Deploy';
                deployBtn.title = "Deploy the stack";

                reconcileBtn.addEventListener("click", () =>
                    runStackAction(stack, "reconcile", [
                        reconcileBtn,
                        deployBtn,
                    ]),
                );
                deployBtn.addEventListener("click", () =>
                    runStackAction(stack, "deploy", [reconcileBtn, deployBtn]),
                );

                toolbar.append(editLink, reconcileBtn, deployBtn);
                detailCell.appendChild(toolbar);

                const members = stack.members || [];
                if (members.length === 0) {
                    const empty = document.createElement("div");
                    empty.className = "stack-detail-empty";
                    empty.textContent =
                        "No containers associated with this stack.";
                    detailCell.appendChild(empty);
                } else {
                    detailCell.appendChild(memberTable(members));
                }
                detailRow.appendChild(detailCell);
                tableBodyEl.appendChild(detailRow);
            }
        });
    };

    const sorter = page.createTableSorter(
        () => {
            if (pager) pager.reset();
            renderRows();
        },
        { key: "name" },
    );

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".stacks-table",
            storageKey: "dockgo_columns_stacks",
        });
    }

    if (page && page.createPager) {
        pager = page.createPager({
            tableSelector: ".stacks-table",
            onChange: renderRows,
        });
    }

    const setBusy = (busy) => {
        [refreshBtn, refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
            button.classList.toggle("spinning", busy);
        });
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

    const fetchStacks = async ({ showLoading = false, busy = false } = {}) => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        if (busy) setBusy(true);
        hideStatus();
        if (showLoading && emptyEl) {
            emptyEl.textContent = "Loading stacks...";
            emptyEl.classList.remove("hidden");
        }

        try {
            const response = await fetch(
                page.withAgentQuery("/api/stacks/overview"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                showStatus("Authentication required to list stacks.");
                return false;
            }
            if (!response.ok) {
                throw new Error(await responseErrorMessage(response));
            }

            rows = await response.json();
            renderRows();
            return true;
        } catch (error) {
            console.error("Failed to fetch stacks:", error);
            showStatus(`Failed to load stacks: ${error.message}`);
            if (showLoading && emptyEl) emptyEl.classList.add("hidden");
            return false;
        } finally {
            if (busy) setBusy(false);
        }
    };

    const stackActionMessages = {
        deploy: {
            title: "Deploy Stack",
            label: "Deploy",
            start: "Starting stack deployment...",
            success: "Deployment completed successfully.",
            failure: "Deployment failed",
        },
        reconcile: {
            title: "Reconcile Stack",
            label: "Reconcile",
            start: "Reconciling stack ownership...",
            success: "Stack ownership reconciled.",
            failure: "Reconcile failed",
        },
    };

    const runStackAction = async (stack, action, buttons = []) => {
        const messages = stackActionMessages[action];
        if (!messages || !page) return;

        const confirmed = await page.showConfirmModal({
            title: messages.title,
            message:
                action === "deploy"
                    ? `Deploy "${stack.name}"? This may pull images and recreate its containers.`
                    : `Reconcile "${stack.name}"? This re-binds recorded ownership to the current runtime containers.`,
            confirmLabel: messages.label,
            danger: action === "deploy",
        });
        if (!confirmed) return;

        buttons.forEach((button) => {
            if (button) button.disabled = true;
        });
        hideStatus();
        showStatus(`${messages.start} (${stack.name})`, "info");

        try {
            const response = await fetch(
                page.withAgentQuery(
                    `/api/stacks/${encodeURIComponent(stack.id)}/${action}`,
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

            if (action === "reconcile") {
                await response.json().catch(() => null);
            } else if (response.body) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = "";
                let streamError = "";
                let sawDone = false;

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
                        } catch (parseError) {
                            console.error(
                                "Failed to parse stack action event",
                                parseError,
                            );
                            continue;
                        }
                        if (event.type === "start") {
                            showStatus(
                                event.message ||
                                    `${messages.start} (${stack.name})`,
                                "info",
                            );
                        } else if (event.type === "progress") {
                            showStatus(event.status || "Working...", "info");
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
                    console.warn(
                        `Stack ${stack.name} action stream ended without a done event`,
                    );
                }
            }

            const refreshed = await fetchStacks();
            if (refreshed) {
                showStatus(messages.success, "success");
            }
        } catch (error) {
            console.error(`Failed to ${action} stack:`, error);
            await fetchStacks();
            showStatus(`${messages.failure}: ${error.message}`);
        } finally {
            buttons.forEach((button) => {
                if (button) button.disabled = false;
            });
        }
    };

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => fetchStacks({ busy: true }));
    }
    if (refreshListBtn) {
        refreshListBtn.addEventListener("click", () =>
            fetchStacks({ busy: true }),
        );
    }

    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && rows.length > 0) {
            fetchStacks();
        }
    });

    if (page) {
        page.init({
            onReady: () => fetchStacks({ showLoading: true }),
            onLogin: () => fetchStacks({ showLoading: true }),
            onHostChange: () => {
                if (pager) pager.reset();
                fetchStacks({ showLoading: true });
            },
        });
    }

    window.setInterval(() => {
        if (!document.hidden && rows.length > 0) {
            fetchStacks();
        }
    }, 10000);
});

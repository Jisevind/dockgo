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
    const expanded = new Set();

    const statusIcons = {
        running: "▶",
        stopped: "■",
        unknown: "•",
    };

    const stackSortValue = (stack, key) => {
        switch (key) {
            case "name":
                return (stack.name || "").toLowerCase();
            case "status":
                return (stack.status || "").toLowerCase();
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
        badge.className = `state-badge state-${normalized}`;
        badge.textContent = `${statusIcons[normalized] || "•"} ${normalized}`;
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
            stateCell.appendChild(stateBadge(member.state));

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
            return;
        }
        emptyEl.classList.add("hidden");

        sorter.sort(rows, stackSortValue).forEach((stack) => {
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
                const detailCell = document.createElement("td");
                detailCell.colSpan = 11;
                const members = stack.members || [];
                if (members.length === 0) {
                    detailCell.textContent =
                        "No containers associated with this stack.";
                    detailCell.className = "stack-detail-empty";
                } else {
                    detailCell.appendChild(memberTable(members));
                }
                detailRow.appendChild(detailCell);
                tableBodyEl.appendChild(detailRow);
            }
        });
    };

    const sorter = page.createTableSorter(() => renderRows(), { key: "name" });

    const setBusy = (busy) => {
        [refreshBtn, refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
            button.classList.toggle("spinning", busy);
        });
    };

    const fetchStacks = async ({ showLoading = false, busy = false } = {}) => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        if (busy) setBusy(true);
        if (statusEl) statusEl.classList.add("hidden");
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
                if (statusEl) {
                    statusEl.textContent =
                        "Authentication required to list stacks.";
                    statusEl.classList.remove("hidden");
                }
                return;
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            rows = await response.json();
            renderRows();
        } catch (error) {
            console.error("Failed to fetch stacks:", error);
            if (statusEl) {
                statusEl.textContent = `Failed to load stacks: ${error.message}`;
                statusEl.classList.remove("hidden");
            }
            if (showLoading && emptyEl) emptyEl.classList.add("hidden");
        } finally {
            if (busy) setBusy(false);
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
            onHostChange: () => fetchStacks({ showLoading: true }),
        });
    }

    window.setInterval(() => {
        if (!document.hidden && rows.length > 0) {
            fetchStacks();
        }
    }, 10000);
});

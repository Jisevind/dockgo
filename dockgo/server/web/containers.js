/* Containers page: live table with state, health, and resource usage. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("containers-table-body");
    const emptyEl = document.getElementById("containers-empty");
    const statusEl = document.getElementById("containers-status");
    const refreshBtn = document.getElementById("refresh-containers-btn");
    const refreshListBtn = document.getElementById(
        "refresh-containers-list-btn",
    );

    const page = window.DockGoPage;

    let rows = [];
    let sortKey = "name";
    let sortDir = 1;

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

    const formatUptime = (seconds, ago) => {
        if (!Number.isFinite(seconds) || seconds <= 0) return "-";
        let value;
        if (seconds < 60) {
            value = `${Math.floor(seconds)}s`;
        } else if (seconds < 3600) {
            const minutes = Math.floor(seconds / 60);
            value = `${minutes} minute${minutes === 1 ? "" : "s"}`;
        } else if (seconds < 86400) {
            const hours = Math.floor(seconds / 3600);
            value = `${hours} hour${hours === 1 ? "" : "s"}`;
        } else {
            const days = Math.floor(seconds / 86400);
            value = `${days} day${days === 1 ? "" : "s"}`;
        }
        return ago ? `${value} ago` : value;
    };

    const sortValue = (container, key) => {
        switch (key) {
            case "name":
                return (container.name || "").toLowerCase();
            case "image":
                return (container.image || "").toLowerCase();
            case "state":
                return (container.state || "").toLowerCase();
            case "health":
                return (container.health || "").toLowerCase();
            case "uptime":
                return container.uptime_seconds || 0;
            case "restarts":
                return container.restart_count || 0;
            case "cpu":
                return container.cpu_percent || 0;
            case "memory":
                return container.memory_used || 0;
            case "net":
                return (container.net_rx || 0) + (container.net_tx || 0);
            case "disk":
                return (container.disk_read || 0) + (container.disk_write || 0);
            case "ip":
                return (container.ip || "").toLowerCase();
            case "ports":
                return (container.ports || []).join(",").toLowerCase();
            case "stack":
                return (container.compose_project || "").toLowerCase();
            default:
                return "";
        }
    };

    const renderRows = () => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (rows.length === 0) {
            emptyEl.textContent = "No containers found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        const sorted = rows.slice().sort((a, b) => {
            const left = sortValue(a, sortKey);
            const right = sortValue(b, sortKey);
            if (typeof left === "number" && typeof right === "number") {
                return (left - right) * sortDir;
            }
            return String(left).localeCompare(String(right)) * sortDir;
        });

        sorted.forEach((container) => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const name = document.createElement("span");
            name.className = "container-table-name";
            name.textContent = container.name || "-";
            nameCell.appendChild(name);

            const imageCell = document.createElement("td");
            const image = document.createElement("span");
            image.className = "container-table-image";
            image.textContent = container.image || "-";
            imageCell.appendChild(image);

            const stateCell = document.createElement("td");
            const state = container.state || "unknown";
            const stateWrap = document.createElement("div");
            stateWrap.className = "state-cell";
            const stateBadge = document.createElement("span");
            stateBadge.className = `status-badge ${stateStatusClass(state)}`;
            stateBadge.textContent = state;
            stateWrap.appendChild(stateBadge);
            stateWrap.appendChild(
                page.createContainerActionButton({
                    name: container.name,
                    state,
                    onDone: () => window.setTimeout(fetchContainers, 800),
                    onError: (message) => showStatus(message),
                }),
            );
            stateCell.appendChild(stateWrap);

            const healthCell = document.createElement("td");
            if (container.health) {
                const dot = document.createElement("span");
                dot.className = `health-dot health-${container.health}`;
                dot.title = container.health;
                healthCell.appendChild(dot);
            } else {
                healthCell.textContent = "-";
            }

            const uptimeCell = document.createElement("td");
            uptimeCell.className = "cell-data";
            uptimeCell.textContent = formatUptime(
                container.uptime_seconds,
                container.uptime_ago,
            );

            const restartsCell = document.createElement("td");
            restartsCell.className = "cell-data";
            restartsCell.textContent = String(container.restart_count ?? 0);

            const cpuCell = document.createElement("td");
            cpuCell.className = "cell-data";
            cpuCell.textContent =
                container.state === "running"
                    ? `${(container.cpu_percent || 0).toFixed(1)}%`
                    : "-";

            const memoryCell = document.createElement("td");
            memoryCell.className = "cell-data";
            if (container.memory_limit) {
                const memory = document.createElement("span");
                memory.textContent = `${page.formatBytesCompact(container.memory_used)}/${page.formatBytesCompact(container.memory_limit)}`;
                if (
                    container.memory_used / container.memory_limit >= 0.75
                ) {
                    memory.className = "memory-warning";
                }
                memoryCell.appendChild(memory);
            } else {
                memoryCell.textContent = "-";
            }

            const netCell = document.createElement("td");
            netCell.className = "cell-data";
            netCell.textContent =
                container.state === "running"
                    ? `↓${page.formatBytesCompact(container.net_rx)} ↑${page.formatBytesCompact(container.net_tx)}`
                    : "-";

            const diskCell = document.createElement("td");
            diskCell.className = "cell-data";
            diskCell.textContent =
                container.state === "running"
                    ? `r${page.formatBytesCompact(container.disk_read)} w${page.formatBytesCompact(container.disk_write)}`
                    : "-";

            const ipCell = document.createElement("td");
            ipCell.className = "cell-data";
            ipCell.textContent = container.ip || "-";

            const portsCell = document.createElement("td");
            const ports = container.ports || [];
            if (ports.length === 0) {
                portsCell.textContent = "-";
            } else {
                ports.forEach((port) => {
                    const badge = document.createElement("span");
                    badge.className = "port-badge";
                    badge.textContent = port;
                    portsCell.appendChild(badge);
                });
            }

            const autoUpdateCell = document.createElement("td");
            autoUpdateCell.textContent = "-";

            const stackCell = document.createElement("td");
            if (container.compose_project) {
                const stack = document.createElement("span");
                stack.className = "stack-tag";
                stack.textContent = container.compose_project;
                stackCell.appendChild(stack);
            } else {
                stackCell.textContent = "-";
            }

            row.append(
                nameCell,
                imageCell,
                stateCell,
                healthCell,
                uptimeCell,
                restartsCell,
                cpuCell,
                memoryCell,
                netCell,
                diskCell,
                ipCell,
                portsCell,
                autoUpdateCell,
                stackCell,
            );
            tableBodyEl.appendChild(row);
        });

        document.querySelectorAll(".sort-btn").forEach((button) => {
            const arrow = button.querySelector(".sort-arrow");
            if (!arrow) return;
            if (button.dataset.sort === sortKey) {
                arrow.textContent = sortDir === 1 ? "↑" : "↓";
            } else {
                arrow.textContent = "↕";
            }
        });
    };

    const setBusy = (busy) => {
        [refreshBtn, refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
            button.classList.toggle("spinning", busy);
        });
    };

    const showStatus = (message) => {
        if (!statusEl) return;
        statusEl.textContent = message;
        statusEl.classList.remove("hidden");
    };

    const fetchContainers = async ({ showLoading = false, busy = false } = {}) => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        if (busy) setBusy(true);
        if (statusEl) statusEl.classList.add("hidden");
        if (showLoading && emptyEl) {
            emptyEl.textContent = "Loading containers...";
            emptyEl.classList.remove("hidden");
        }

        try {
            const response = await fetch(
                page.withAgentQuery("/api/containers/overview"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                if (statusEl) {
                    statusEl.textContent =
                        "Authentication required to list containers.";
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
            console.error("Failed to fetch containers:", error);
            if (statusEl) {
                statusEl.textContent = `Failed to load containers: ${error.message}`;
                statusEl.classList.remove("hidden");
            }
            if (showLoading && emptyEl) emptyEl.classList.add("hidden");
        } finally {
            if (busy) setBusy(false);
        }
    };

    document.querySelectorAll(".sort-btn").forEach((button) => {
        button.addEventListener("click", () => {
            const key = button.dataset.sort;
            if (sortKey === key) {
                sortDir = -sortDir;
            } else {
                sortKey = key;
                sortDir = 1;
            }
            renderRows();
        });
    });

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".containers-table",
            storageKey: "dockgo_columns_containers",
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () =>
            fetchContainers({ busy: true }),
        );
    }
    if (refreshListBtn) {
        refreshListBtn.addEventListener("click", () =>
            fetchContainers({ busy: true }),
        );
    }

    document.addEventListener("visibilitychange", () => {
        if (!document.hidden && rows.length > 0) {
            fetchContainers();
        }
    });

    if (page) {
        page.init({
            onReady: () => fetchContainers({ showLoading: true }),
            onLogin: () => fetchContainers({ showLoading: true }),
            onHostChange: () => fetchContainers({ showLoading: true }),
        });
    }

    window.setInterval(() => {
        if (!document.hidden && rows.length > 0) {
            fetchContainers();
        }
    }, 10000);
});

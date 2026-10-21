/* Volumes page: lists Docker volumes for the selected host. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("volumes-table-body");
    const emptyEl = document.getElementById("volumes-empty");
    const statusEl = document.getElementById("volumes-status");
    const refreshBtn = document.getElementById("refresh-volumes-btn");
    const refreshListBtn = document.getElementById(
        "refresh-volumes-list-btn",
    );

    const page = window.DockGoPage;

    const volumeSortValue = (volume, key) => {
        switch (key) {
            case "name":
                return (volume.name || "").toLowerCase();
            case "driver":
                return (volume.driver || "").toLowerCase();
            case "scope":
                return (volume.scope || "").toLowerCase();
            case "stack":
                return (volume.stacks || []).join(",").toLowerCase();
            case "usedby":
                return (volume.used_by || []).join(",").toLowerCase();
            case "created":
                return Date.parse(volume.created_at) || 0;
            case "containers":
                return volume.containers || 0;
            default:
                return "";
        }
    };

    let rows = [];
    const expanded = new Set();
    const detailCache = new Map();
    const detailLoading = new Set();

    const renderVolumeDetail = (detail) => {
        const wrapper = document.createElement("div");
        wrapper.className = "network-detail";

        const containersSection = document.createElement("section");
        containersSection.className = "network-detail-section";
        const containersTitle = document.createElement("h4");
        containersTitle.textContent = "Containers Using This Volume";
        containersSection.appendChild(containersTitle);

        const containers = detail.containers || [];
        if (containers.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No containers use this volume.";
            containersSection.appendChild(empty);
        } else {
            const table = document.createElement("table");
            table.className = "stack-containers-table";

            const head = document.createElement("thead");
            const headRow = document.createElement("tr");
            ["Container", "Container ID"].forEach((label) => {
                const th = document.createElement("th");
                th.textContent = label;
                headRow.appendChild(th);
            });
            head.appendChild(headRow);
            table.appendChild(head);

            const body = document.createElement("tbody");
            containers.forEach((container) => {
                const tr = document.createElement("tr");
                const nameCell = document.createElement("td");
                const name = document.createElement("span");
                name.className = "container-table-name";
                name.textContent = container.name || "(unnamed)";
                nameCell.appendChild(name);

                const idCell = document.createElement("td");
                idCell.className = "cell-mono";
                idCell.textContent = container.id || "-";
                idCell.title = container.id || "";

                tr.append(nameCell, idCell);
                body.appendChild(tr);
            });
            table.appendChild(body);
            containersSection.appendChild(table);
        }
        wrapper.appendChild(containersSection);

        const stacksSection = document.createElement("section");
        stacksSection.className = "network-detail-section";
        const stacksTitle = document.createElement("h4");
        stacksTitle.textContent = "Stacks Using This Volume";
        stacksSection.appendChild(stacksTitle);

        const stacks = detail.stacks || [];
        if (stacks.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No Compose stacks use this volume.";
            stacksSection.appendChild(empty);
        } else {
            const list = document.createElement("div");
            list.className = "network-stack-list";
            stacks.forEach((stackName) => {
                const stack = document.createElement("span");
                stack.className = "stack-tag";
                stack.textContent = stackName;
                list.appendChild(stack);
            });
            stacksSection.appendChild(list);
        }
        wrapper.appendChild(stacksSection);

        return wrapper;
    };

    const fetchVolumeDetail = async (name) => {
        if (detailLoading.has(name)) return;
        detailLoading.add(name);

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/volumes/${encodeURIComponent(name)}`),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            detailCache.set(name, { detail: await response.json() });
        } catch (error) {
            console.error(`Failed to fetch volume ${name}:`, error);
            detailCache.set(name, { error: error.message });
        } finally {
            detailLoading.delete(name);
        }

        if (expanded.has(name)) {
            renderVolumes(rows);
        }
    };

    const appendDetailRow = (volume, colspan) => {
        const detailRow = document.createElement("tr");
        detailRow.className = "network-detail-row";
        detailRow.dataset.detailRow = "true";

        const detailCell = document.createElement("td");
        detailCell.colSpan = colspan;

        const cached = detailCache.get(volume.name);
        if (!cached) {
            const loading = document.createElement("div");
            loading.className = "network-detail-empty";
            loading.textContent = "Loading volume details...";
            detailCell.appendChild(loading);
            fetchVolumeDetail(volume.name);
        } else if (cached.error) {
            const error = document.createElement("div");
            error.className = "network-detail-error";
            error.textContent = `Failed to load volume details: ${cached.error}`;
            detailCell.appendChild(error);
        } else {
            detailCell.appendChild(renderVolumeDetail(cached.detail));
        }

        detailRow.appendChild(detailCell);
        tableBodyEl.appendChild(detailRow);
    };

    const renderVolumes = (volumes) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(volumes) || volumes.length === 0) {
            emptyEl.textContent = "No volumes found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        sorter.sort(volumes, volumeSortValue).forEach((volume) => {
            const isExpanded = expanded.has(volume.name);
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const nameWrap = document.createElement("div");
            nameWrap.className = "network-name-cell";

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = `expand-btn${isExpanded ? " expanded" : ""}`;
            toggle.setAttribute(
                "aria-expanded",
                isExpanded ? "true" : "false",
            );
            toggle.setAttribute(
                "aria-label",
                `${isExpanded ? "Collapse" : "Expand"} ${volume.name}`,
            );
            toggle.textContent = "›";
            toggle.addEventListener("click", (event) => {
                event.stopPropagation();
                if (expanded.has(volume.name)) {
                    expanded.delete(volume.name);
                } else {
                    expanded.add(volume.name);
                }
                renderVolumes(rows);
            });

            const nameLink = document.createElement("a");
            nameLink.className = "table-link cell-name";
            nameLink.href = `/volumes/${encodeURIComponent(volume.name)}`;
            nameLink.textContent = volume.name || "(unnamed)";
            nameLink.title = volume.name || "";

            nameWrap.append(toggle, nameLink);
            nameCell.appendChild(nameWrap);

            const driverCell = document.createElement("td");
            const driverBadge = document.createElement("span");
            driverBadge.className = "driver-badge";
            driverBadge.textContent = volume.driver || "unknown";
            driverCell.appendChild(driverBadge);

            const scopeCell = document.createElement("td");
            scopeCell.textContent = volume.scope || "-";

            const stackCell = document.createElement("td");
            const stackNames = (volume.stacks || []).filter(Boolean);
            const stack = document.createElement("span");
            stack.className = "cell-name";
            stack.textContent = stackNames.join(", ") || "-";
            stack.title = stackNames.join(", ");
            stackCell.appendChild(stack);

            const usedByCell = document.createElement("td");
            const usedByNames = (volume.used_by || []).filter(Boolean);
            const usedBy = document.createElement("span");
            usedBy.className = "cell-name";
            usedBy.textContent = usedByNames.join(", ") || "-";
            usedBy.title = usedByNames.join(", ");
            usedByCell.appendChild(usedBy);

            const createdCell = document.createElement("td");
            createdCell.className = "cell-data";
            createdCell.textContent = page.formatDate(volume.created_at);

            const containersCell = document.createElement("td");
            containersCell.className = "cell-data";
            containersCell.textContent = String(volume.containers ?? 0);

            row.append(
                nameCell,
                driverCell,
                scopeCell,
                stackCell,
                usedByCell,
                createdCell,
                containersCell,
            );
            tableBodyEl.appendChild(row);

            if (isExpanded) {
                appendDetailRow(volume, 7);
            }
        });
    };

    const sorter = page.createTableSorter(() => renderVolumes(rows), {
        key: "name",
    });

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".data-table",
            storageKey: "dockgo_columns_volumes",
        });
    }

    const setBusy = (busy) => {
        [refreshBtn, refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
            button.classList.toggle("spinning", busy);
        });
    };

    const fetchVolumes = async () => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        setBusy(true);
        if (statusEl) statusEl.classList.add("hidden");
        if (emptyEl) {
            emptyEl.textContent = "Loading volumes...";
            emptyEl.classList.remove("hidden");
        }
        if (tableBodyEl) tableBodyEl.textContent = "";

        try {
            const response = await fetch(
                page.withAgentQuery("/api/volumes"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                const state = page.getState();
                if (state.authEnabled) page.showLoginModal();
                if (statusEl) {
                    statusEl.textContent =
                        "Authentication required to list volumes.";
                    statusEl.classList.remove("hidden");
                }
                if (emptyEl) emptyEl.classList.add("hidden");
                return;
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            rows = await response.json();
            detailCache.clear();
            detailLoading.clear();
            renderVolumes(rows);
        } catch (error) {
            console.error("Failed to fetch volumes:", error);
            if (emptyEl) emptyEl.classList.add("hidden");
            if (statusEl) {
                statusEl.textContent = `Failed to load volumes: ${error.message}`;
                statusEl.classList.remove("hidden");
            }
        } finally {
            setBusy(false);
        }
    };

    if (refreshBtn) refreshBtn.addEventListener("click", fetchVolumes);
    if (refreshListBtn) refreshListBtn.addEventListener("click", fetchVolumes);

    if (page) {
        page.init({
            onReady: fetchVolumes,
            onLogin: fetchVolumes,
            onHostChange: () => {
                expanded.clear();
                fetchVolumes();
            },
        });
    }
});

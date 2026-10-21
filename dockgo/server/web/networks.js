/* Networks page: lists Docker networks for the selected host. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("networks-table-body");
    const emptyEl = document.getElementById("networks-empty");
    const statusEl = document.getElementById("networks-status");
    const refreshBtn = document.getElementById("refresh-networks-btn");
    const refreshListBtn = document.getElementById(
        "refresh-networks-list-btn",
    );

    const page = window.DockGoPage;

    const networkDriverClass = (driver) => {
        const known = [
            "bridge",
            "host",
            "null",
            "overlay",
            "macvlan",
            "ipvlan",
        ];
        return known.includes(driver)
            ? `driver-badge driver-${driver}`
            : "driver-badge";
    };

    const networkSortValue = (network, key) => {
        switch (key) {
            case "name":
                return (network.name || "").toLowerCase();
            case "driver":
                return (network.driver || "").toLowerCase();
            case "scope":
                return (network.scope || "").toLowerCase();
            case "subnet":
                return (network.subnets || []).join(",").toLowerCase();
            case "gateway":
                return (network.gateways || []).join(",").toLowerCase();
            case "containers":
                return network.containers || 0;
            default:
                return "";
        }
    };

    let rows = [];
    const expanded = new Set();
    const detailCache = new Map();
    const detailLoading = new Set();

    const renderNetworkDetail = (detail) => {
        const wrapper = document.createElement("div");
        wrapper.className = "network-detail";

        const containersSection = document.createElement("section");
        containersSection.className = "network-detail-section";
        const containersTitle = document.createElement("h4");
        containersTitle.textContent = "Containers Using This Network";
        containersSection.appendChild(containersTitle);

        const containers = detail.containers || [];
        if (containers.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No containers are connected to this network.";
            containersSection.appendChild(empty);
        } else {
            const table = document.createElement("table");
            table.className = "stack-containers-table";

            const head = document.createElement("thead");
            const headRow = document.createElement("tr");
            ["Container", "IPv4", "IPv6", "Stack"].forEach((label) => {
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
                name.textContent = container.name || container.id || "-";
                nameCell.appendChild(name);

                const ipv4Cell = document.createElement("td");
                ipv4Cell.className = "cell-data";
                ipv4Cell.textContent = container.ipv4_address || "-";

                const ipv6Cell = document.createElement("td");
                ipv6Cell.className = "cell-data";
                ipv6Cell.textContent = container.ipv6_address || "-";

                const stackCell = document.createElement("td");
                if (container.stack) {
                    const stack = document.createElement("span");
                    stack.className = "stack-tag";
                    stack.textContent = container.stack;
                    stackCell.appendChild(stack);
                } else {
                    stackCell.textContent = "-";
                }

                tr.append(nameCell, ipv4Cell, ipv6Cell, stackCell);
                body.appendChild(tr);
            });
            table.appendChild(body);
            containersSection.appendChild(table);
        }
        wrapper.appendChild(containersSection);

        const stacksSection = document.createElement("section");
        stacksSection.className = "network-detail-section";
        const stacksTitle = document.createElement("h4");
        stacksTitle.textContent = "Stacks Using This Network";
        stacksSection.appendChild(stacksTitle);

        const stacks = detail.stacks || [];
        if (stacks.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No Compose stacks use this network.";
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

    const fetchNetworkDetail = async (name) => {
        if (detailLoading.has(name)) return;
        detailLoading.add(name);

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/networks/${encodeURIComponent(name)}`),
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
            console.error(`Failed to fetch network ${name}:`, error);
            detailCache.set(name, { error: error.message });
        } finally {
            detailLoading.delete(name);
        }

        if (expanded.has(name)) {
            renderNetworks(rows);
        }
    };

    const appendDetailRow = (network) => {
        const detailRow = document.createElement("tr");
        detailRow.className = "network-detail-row";
        detailRow.dataset.detailRow = "true";

        const detailCell = document.createElement("td");
        detailCell.colSpan = 6;

        const cached = detailCache.get(network.name);
        if (!cached) {
            const loading = document.createElement("div");
            loading.className = "network-detail-empty";
            loading.textContent = "Loading network details...";
            detailCell.appendChild(loading);
            fetchNetworkDetail(network.name);
        } else if (cached.error) {
            const error = document.createElement("div");
            error.className = "network-detail-error";
            error.textContent = `Failed to load network details: ${cached.error}`;
            detailCell.appendChild(error);
        } else {
            detailCell.appendChild(renderNetworkDetail(cached.detail));
        }

        detailRow.appendChild(detailCell);
        tableBodyEl.appendChild(detailRow);
    };

    const renderNetworks = (networks) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(networks) || networks.length === 0) {
            emptyEl.textContent = "No networks found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        sorter.sort(networks, networkSortValue).forEach((network) => {
            const row = document.createElement("tr");
            const isExpanded = expanded.has(network.name);

            const nameCell = document.createElement("td");
            const nameCellWrap = document.createElement("div");
            nameCellWrap.className = "network-name-cell";

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = `expand-btn${isExpanded ? " expanded" : ""}`;
            toggle.setAttribute(
                "aria-expanded",
                isExpanded ? "true" : "false",
            );
            toggle.setAttribute(
                "aria-label",
                `${isExpanded ? "Collapse" : "Expand"} ${network.name}`,
            );
            toggle.textContent = "›";
            toggle.addEventListener("click", (event) => {
                event.stopPropagation();
                if (expanded.has(network.name)) {
                    expanded.delete(network.name);
                } else {
                    expanded.add(network.name);
                }
                renderNetworks(rows);
            });

            const nameWrap = document.createElement("span");
            nameWrap.className = "network-name";
            nameWrap.textContent = network.name || "(unnamed)";
            if (network.built_in) {
                const builtIn = document.createElement("span");
                builtIn.className = "builtin-badge";
                builtIn.textContent = "built-in";
                nameWrap.appendChild(builtIn);
            }

            nameCellWrap.append(toggle, nameWrap);
            nameCell.appendChild(nameCellWrap);

            const driverCell = document.createElement("td");
            const driverBadge = document.createElement("span");
            driverBadge.className = networkDriverClass(network.driver);
            driverBadge.textContent = network.driver || "unknown";
            driverCell.appendChild(driverBadge);

            const scopeCell = document.createElement("td");
            scopeCell.textContent = network.scope || "-";

            const subnetCell = document.createElement("td");
            subnetCell.className = "cell-data";
            subnetCell.textContent =
                (network.subnets || []).filter(Boolean).join(", ") || "-";

            const gatewayCell = document.createElement("td");
            gatewayCell.className = "cell-data";
            gatewayCell.textContent =
                (network.gateways || []).filter(Boolean).join(", ") || "-";

            const containersCell = document.createElement("td");
            containersCell.className = "cell-data";
            containersCell.textContent = String(network.containers ?? 0);

            row.append(
                nameCell,
                driverCell,
                scopeCell,
                subnetCell,
                gatewayCell,
                containersCell,
            );
            tableBodyEl.appendChild(row);

            if (isExpanded) {
                appendDetailRow(network);
            }
        });
    };

    const sorter = page.createTableSorter(() => renderNetworks(rows), {
        key: "name",
    });

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".data-table",
            storageKey: "dockgo_columns_networks",
        });
    }

    const setBusy = (busy) => {
        [refreshBtn, refreshListBtn].forEach((button) => {
            if (!button) return;
            button.disabled = busy;
            button.classList.toggle("spinning", busy);
        });
    };

    const fetchNetworks = async () => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        setBusy(true);
        if (statusEl) statusEl.classList.add("hidden");
        if (emptyEl) {
            emptyEl.textContent = "Loading networks...";
            emptyEl.classList.remove("hidden");
        }
        if (tableBodyEl) tableBodyEl.textContent = "";

        try {
            const response = await fetch(
                page.withAgentQuery("/api/networks"),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 401 || response.status === 403) {
                const state = page.getState();
                if (state.authEnabled) page.showLoginModal();
                if (statusEl) {
                    statusEl.textContent =
                        "Authentication required to list networks.";
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
            renderNetworks(rows);
        } catch (error) {
            console.error("Failed to fetch networks:", error);
            if (emptyEl) emptyEl.classList.add("hidden");
            if (statusEl) {
                statusEl.textContent = `Failed to load networks: ${error.message}`;
                statusEl.classList.remove("hidden");
            }
        } finally {
            setBusy(false);
        }
    };

    if (refreshBtn) refreshBtn.addEventListener("click", fetchNetworks);
    if (refreshListBtn) refreshListBtn.addEventListener("click", fetchNetworks);

    if (page) {
        page.init({
            onReady: fetchNetworks,
            onLogin: fetchNetworks,
            onHostChange: () => {
                expanded.clear();
                fetchNetworks();
            },
        });
    }
});

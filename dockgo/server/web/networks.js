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

    const renderNetworks = (networks) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(networks) || networks.length === 0) {
            emptyEl.textContent = "No networks found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        networks.forEach((network) => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const nameWrap = document.createElement("span");
            nameWrap.className = "network-name";
            nameWrap.textContent = network.name || "(unnamed)";
            nameCell.appendChild(nameWrap);
            if (network.built_in) {
                const builtIn = document.createElement("span");
                builtIn.className = "builtin-badge";
                builtIn.textContent = "built-in";
                nameWrap.appendChild(builtIn);
            }

            const driverCell = document.createElement("td");
            const driverBadge = document.createElement("span");
            driverBadge.className = networkDriverClass(network.driver);
            driverBadge.textContent = network.driver || "unknown";
            driverCell.appendChild(driverBadge);

            const scopeCell = document.createElement("td");
            scopeCell.textContent = network.scope || "-";

            const subnetCell = document.createElement("td");
            subnetCell.textContent =
                (network.subnets || []).filter(Boolean).join(", ") || "-";

            const gatewayCell = document.createElement("td");
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
        });
    };

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

            renderNetworks(await response.json());
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
            onHostChange: fetchNetworks,
        });
    }
});

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

    const renderVolumes = (volumes) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(volumes) || volumes.length === 0) {
            emptyEl.textContent = "No volumes found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        volumes.forEach((volume) => {
            const row = document.createElement("tr");

            const nameCell = document.createElement("td");
            const nameLink = document.createElement("a");
            nameLink.className = "table-link cell-name";
            nameLink.href = `/volumes/${encodeURIComponent(volume.name)}`;
            nameLink.textContent = volume.name || "(unnamed)";
            nameLink.title = volume.name || "";
            nameCell.appendChild(nameLink);

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
        });
    };

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

            renderVolumes(await response.json());
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
            onHostChange: fetchVolumes,
        });
    }
});

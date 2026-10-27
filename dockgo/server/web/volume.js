/* Volume overview page. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const nameEl = document.getElementById("volume-name");
    const badgesEl = document.getElementById("volume-badges");
    const errorEl = document.getElementById("volume-error");
    const loadingEl = document.getElementById("volume-loading");
    const contentEl = document.getElementById("volume-content");
    const driverEl = document.getElementById("volume-driver");
    const scopeEl = document.getElementById("volume-scope");
    const createdEl = document.getElementById("volume-created");
    const mountpointEl = document.getElementById("volume-mountpoint");
    const containersEl = document.getElementById("volume-containers");
    const labelsEl = document.getElementById("volume-labels");
    const refreshBtn = document.getElementById("refresh-volume-btn");

    const page = window.DockGoPage;

    const volumeName = () => {
        const prefix = "/volumes/";
        if (!window.location.pathname.startsWith(prefix)) return "";
        return decodeURIComponent(
            window.location.pathname.slice(prefix.length).replace(/\/+$/, ""),
        );
    };

    const addBadge = (text, className) => {
        const badge = document.createElement("span");
        badge.className = className;
        badge.textContent = text;
        badgesEl.appendChild(badge);
    };

    const renderContainers = (containers) => {
        containersEl.textContent = "";
        if (!Array.isArray(containers) || containers.length === 0) {
            const empty = document.createElement("div");
            empty.className = "loading";
            empty.textContent = "No containers are using this volume.";
            containersEl.appendChild(empty);
            return;
        }

        containers.forEach((container) => {
            const row = document.createElement("div");
            row.className = "volume-container-row";

            const name = document.createElement("span");
            name.className = "volume-container-name";
            name.textContent = container.name || "(unnamed)";

            const id = document.createElement("span");
            id.className = "cell-mono volume-container-id";
            id.textContent = container.id || "-";
            id.title = container.id || "";

            row.append(name, id);
            containersEl.appendChild(row);
        });
    };

    const renderLabels = (labels) => {
        labelsEl.textContent = "";
        const keys = Object.keys(labels || {}).sort();
        if (keys.length === 0) {
            const empty = document.createElement("div");
            empty.className = "loading";
            empty.textContent = "No labels.";
            labelsEl.appendChild(empty);
            return;
        }

        keys.forEach((key) => {
            const card = document.createElement("div");
            card.className = "label-card";

            const keyEl = document.createElement("div");
            keyEl.className = "label-key";
            keyEl.textContent = key.toUpperCase();

            const valueEl = document.createElement("div");
            valueEl.className = "label-value";
            valueEl.textContent = labels[key];

            card.append(keyEl, valueEl);
            labelsEl.appendChild(card);
        });
    };

    const renderVolume = (volume) => {
        document.title = `${volume.name} · DockGo`;
        nameEl.textContent = volume.name;

        badgesEl.textContent = "";
        if (
            Array.isArray(volume.containers) &&
            volume.containers.length > 0
        ) {
            addBadge("In Use", "status-badge status-running");
        }
        addBadge(volume.scope || "local", "status-badge volume-badge-scope");
        addBadge(volume.driver || "local", "status-badge volume-badge-driver");

        driverEl.textContent = volume.driver || "-";
        scopeEl.textContent = volume.scope || "-";
        createdEl.textContent = page.formatDate(volume.created_at);
        mountpointEl.textContent = volume.mountpoint || "-";
        mountpointEl.title = volume.mountpoint || "";

        renderContainers(volume.containers);
        renderLabels(volume.labels);

        loadingEl.classList.add("hidden");
        contentEl.classList.remove("hidden");
    };

    const setError = (message) => {
        loadingEl.classList.add("hidden");
        contentEl.classList.add("hidden");
        errorEl.textContent = message;
        errorEl.classList.remove("hidden");
    };

    const fetchVolume = async () => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        const name = volumeName();
        if (!name) {
            setError("No volume name was provided.");
            return;
        }

        if (refreshBtn) {
            refreshBtn.disabled = true;
            refreshBtn.classList.add("spinning");
        }
        errorEl.classList.add("hidden");

        try {
            const response = await fetch(
                page.withAgentQuery(`/api/volumes/${encodeURIComponent(name)}`),
                { headers: page.getAuthHeaders() },
            );

            if (response.status === 404) {
                setError(`Volume "${name}" was not found.`);
                return;
            }
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                setError("Authentication required to view this volume.");
                return;
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            renderVolume(await response.json());
        } catch (error) {
            console.error("Failed to fetch volume:", error);
            setError(`Failed to load volume: ${error.message}`);
        } finally {
            if (refreshBtn) {
                refreshBtn.disabled = false;
                refreshBtn.classList.remove("spinning");
            }
        }
    };

    if (refreshBtn) refreshBtn.addEventListener("click", fetchVolume);

    if (page) {
        page.init({
            onReady: fetchVolume,
            onLogin: fetchVolume,
            onHostChange: fetchVolume,
        });
    }
});

/* Images page: lists Docker images for the selected host. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const tableBodyEl = document.getElementById("images-table-body");
    const emptyEl = document.getElementById("images-empty");
    const statusEl = document.getElementById("images-status");
    const refreshBtn = document.getElementById("refresh-images-btn");
    const refreshListBtn = document.getElementById("refresh-images-list-btn");

    const page = window.DockGoPage;

    const shortID = (id) => (id || "").replace(/^sha256:/, "").slice(0, 12);

    const renderImages = (images) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(images) || images.length === 0) {
            emptyEl.textContent = "No images found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        images.forEach((image) => {
            const row = document.createElement("tr");

            const repositoryCell = document.createElement("td");
            const repository = document.createElement("span");
            repository.className = "cell-name";
            repository.textContent = image.repository || "<none>";
            repository.title = image.repository || "";
            repositoryCell.appendChild(repository);

            const tagCell = document.createElement("td");
            const tagBadge = document.createElement("span");
            tagBadge.className = "tag-badge";
            tagBadge.textContent = image.tag || "<none>";
            tagCell.appendChild(tagBadge);

            const idCell = document.createElement("td");
            const idSpan = document.createElement("span");
            idSpan.className = "cell-mono";
            idSpan.textContent = shortID(image.id);
            idSpan.title = image.id || "";
            idCell.appendChild(idSpan);

            const createdCell = document.createElement("td");
            createdCell.className = "cell-data";
            createdCell.textContent = page.formatDate(image.created);

            const sizeCell = document.createElement("td");
            sizeCell.className = "cell-data";
            sizeCell.textContent = page.formatBytes(image.size);

            const containersCell = document.createElement("td");
            containersCell.className = "cell-data";
            containersCell.textContent = String(image.containers ?? 0);

            row.append(
                repositoryCell,
                tagCell,
                idCell,
                createdCell,
                sizeCell,
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

    const fetchImages = async () => {
        if (!page) {
            console.error("DockGoPage is not loaded");
            return;
        }

        setBusy(true);
        if (statusEl) statusEl.classList.add("hidden");
        if (emptyEl) {
            emptyEl.textContent = "Loading images...";
            emptyEl.classList.remove("hidden");
        }
        if (tableBodyEl) tableBodyEl.textContent = "";

        try {
            const response = await fetch(page.withAgentQuery("/api/images"), {
                headers: page.getAuthHeaders(),
            });

            if (response.status === 401 || response.status === 403) {
                const state = page.getState();
                if (state.authEnabled) page.showLoginModal();
                if (statusEl) {
                    statusEl.textContent =
                        "Authentication required to list images.";
                    statusEl.classList.remove("hidden");
                }
                if (emptyEl) emptyEl.classList.add("hidden");
                return;
            }
            if (!response.ok) {
                const message = (await response.text()).trim();
                throw new Error(message || `HTTP ${response.status}`);
            }

            renderImages(await response.json());
        } catch (error) {
            console.error("Failed to fetch images:", error);
            if (emptyEl) emptyEl.classList.add("hidden");
            if (statusEl) {
                statusEl.textContent = `Failed to load images: ${error.message}`;
                statusEl.classList.remove("hidden");
            }
        } finally {
            setBusy(false);
        }
    };

    if (refreshBtn) refreshBtn.addEventListener("click", fetchImages);
    if (refreshListBtn) refreshListBtn.addEventListener("click", fetchImages);

    if (page) {
        page.init({
            onReady: fetchImages,
            onLogin: fetchImages,
            onHostChange: fetchImages,
        });
    }
});

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

    const stateStatusClass = (state) => {
        switch (state) {
            case "running":
                return "status-running";
            case "exited":
            case "dead":
                return "status-exited";
            default:
                return "status-other";
        }
    };

    const imageSortValue = (image, key) => {
        switch (key) {
            case "repository":
                return (image.repository || "").toLowerCase();
            case "tag":
                return (image.tag || "").toLowerCase();
            case "id":
                return (image.id || "").toLowerCase();
            case "created":
                return image.created || 0;
            case "size":
                return image.size || 0;
            case "containers":
                return image.containers || 0;
            default:
                return "";
        }
    };

    const rowKey = (image) =>
        `${image.id}|${image.repository || ""}|${image.tag || ""}`;

    let rows = [];
    const expanded = new Set();
    const detailCache = new Map();
    const detailLoading = new Set();

    const renderImageDetail = (detail) => {
        const wrapper = document.createElement("div");
        wrapper.className = "network-detail";

        const containersSection = document.createElement("section");
        containersSection.className = "network-detail-section";
        const containersTitle = document.createElement("h4");
        containersTitle.textContent = "Containers Using This Image";
        containersSection.appendChild(containersTitle);

        const containers = detail.containers || [];
        if (containers.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No containers use this image.";
            containersSection.appendChild(empty);
        } else {
            const table = document.createElement("table");
            table.className = "stack-containers-table";

            const head = document.createElement("thead");
            const headRow = document.createElement("tr");
            ["Container", "State", "Stack"].forEach((label) => {
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

                const stateCell = document.createElement("td");
                const state = container.state || "unknown";
                const stateBadge = document.createElement("span");
                stateBadge.className = `status-badge ${stateStatusClass(state)}`;
                stateBadge.textContent = state;
                stateCell.appendChild(stateBadge);

                const stackCell = document.createElement("td");
                if (container.stack) {
                    const stack = document.createElement("span");
                    stack.className = "stack-tag";
                    stack.textContent = container.stack;
                    stackCell.appendChild(stack);
                } else {
                    stackCell.textContent = "-";
                }

                tr.append(nameCell, stateCell, stackCell);
                body.appendChild(tr);
            });
            table.appendChild(body);
            containersSection.appendChild(table);
        }
        wrapper.appendChild(containersSection);

        const stacksSection = document.createElement("section");
        stacksSection.className = "network-detail-section";
        const stacksTitle = document.createElement("h4");
        stacksTitle.textContent = "Stacks Using This Image";
        stacksSection.appendChild(stacksTitle);

        const stacks = detail.stacks || [];
        if (stacks.length === 0) {
            const empty = document.createElement("div");
            empty.className = "network-detail-empty";
            empty.textContent = "No Compose stacks use this image.";
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

    const fetchImageDetail = async (image) => {
        if (detailLoading.has(image.id)) return;
        detailLoading.add(image.id);

        try {
            const response = await fetch(
                page.withAgentQuery(
                    `/api/images/${encodeURIComponent(image.id)}`,
                ),
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

            detailCache.set(image.id, { detail: await response.json() });
        } catch (error) {
            console.error(`Failed to fetch image ${image.id}:`, error);
            detailCache.set(image.id, { error: error.message });
        } finally {
            detailLoading.delete(image.id);
        }

        if ([...expanded].some((key) => key.startsWith(`${image.id}|`))) {
            renderImages(rows);
        }
    };

    const appendDetailRow = (image, colspan) => {
        const detailRow = document.createElement("tr");
        detailRow.className = "network-detail-row";
        detailRow.dataset.detailRow = "true";

        const detailCell = document.createElement("td");
        detailCell.colSpan = colspan;

        const cached = detailCache.get(image.id);
        if (!cached) {
            const loading = document.createElement("div");
            loading.className = "network-detail-empty";
            loading.textContent = "Loading image details...";
            detailCell.appendChild(loading);
            fetchImageDetail(image);
        } else if (cached.error) {
            const error = document.createElement("div");
            error.className = "network-detail-error";
            error.textContent = `Failed to load image details: ${cached.error}`;
            detailCell.appendChild(error);
        } else {
            detailCell.appendChild(renderImageDetail(cached.detail));
        }

        detailRow.appendChild(detailCell);
        tableBodyEl.appendChild(detailRow);
    };

    const renderImages = (images) => {
        if (!tableBodyEl || !emptyEl) return;
        tableBodyEl.textContent = "";

        if (!Array.isArray(images) || images.length === 0) {
            emptyEl.textContent = "No images found.";
            emptyEl.classList.remove("hidden");
            return;
        }
        emptyEl.classList.add("hidden");

        sorter.sort(images, imageSortValue).forEach((image) => {
            const key = rowKey(image);
            const isExpanded = expanded.has(key);
            const row = document.createElement("tr");

            const repositoryCell = document.createElement("td");
            const repositoryWrap = document.createElement("div");
            repositoryWrap.className = "network-name-cell";

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = `expand-btn${isExpanded ? " expanded" : ""}`;
            toggle.setAttribute(
                "aria-expanded",
                isExpanded ? "true" : "false",
            );
            toggle.setAttribute(
                "aria-label",
                `${isExpanded ? "Collapse" : "Expand"} ${image.repository || "image"}:${image.tag || "latest"}`,
            );
            toggle.textContent = "›";
            toggle.addEventListener("click", (event) => {
                event.stopPropagation();
                if (expanded.has(key)) {
                    expanded.delete(key);
                } else {
                    expanded.add(key);
                }
                renderImages(rows);
            });

            const repository = document.createElement("span");
            repository.className = "cell-name";
            repository.textContent = image.repository || "<none>";
            repository.title = image.repository || "";

            repositoryWrap.append(toggle, repository);
            repositoryCell.appendChild(repositoryWrap);

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

            if (isExpanded) {
                appendDetailRow(image, 6);
            }
        });
    };

    const sorter = page.createTableSorter(() => renderImages(rows), {
        key: "repository",
    });

    if (page && page.createColumnToggle) {
        page.createColumnToggle({
            tableSelector: ".data-table",
            storageKey: "dockgo_columns_images",
        });
    }

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

            rows = await response.json();
            detailCache.clear();
            detailLoading.clear();
            renderImages(rows);
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
            onHostChange: () => {
                expanded.clear();
                fetchImages();
            },
        });
    }
});

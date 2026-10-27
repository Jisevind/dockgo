/* Shared page chrome for standalone DockGo pages.
 *
 * Owns authentication state, the login/no-auth/confirmation modals, logout
 * controls, the host selector, and the API headers/URL helpers those controls
 * need. The dashboard still uses app.js until it is migrated to its own page.
 */
/* eslint-env browser */
(() => {
    const hostSelector = document.getElementById("host-selector");
    const logoutBtn = document.getElementById("logout-btn");
    const logoutAllBtn = document.getElementById("logout-all-btn");
    const loginModal = document.getElementById("login-modal");
    const loginForm = document.getElementById("login-form");
    const loginError = document.getElementById("login-error");
    const loginUsernameInput = document.getElementById("username");
    const loginPasswordInput = document.getElementById("password");
    const noAuthModal = document.getElementById("no-auth-modal");
    const confirmModal = document.getElementById("confirm-modal");
    const confirmTitleEl = document.getElementById("confirm-modal-title");
    const confirmMessageEl = document.getElementById("confirm-modal-message");
    const confirmCancelBtn = document.getElementById("confirm-modal-cancel");
    const confirmOkBtn = document.getElementById("confirm-modal-ok");

    const urlAgentID =
        new URLSearchParams(window.location.search).get("agent") || "";
    const state = {
        currentAgentID:
            urlAgentID || localStorage.getItem("dockgo_agent_id") || "",
        isLoggedIn: false,
        authEnabled: false,
        apiTokenEnabled: false,
    };

    if (urlAgentID) {
        localStorage.setItem("dockgo_agent_id", urlAgentID);
    }

    let callbacks = {};

    const getCsrfToken = () => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; dockgo_csrf=`);
        if (parts.length === 2) return parts.pop().split(";").shift();
        return "";
    };

    const getAuthHeaders = (includeJSON = false) => {
        const headers = {};
        if (includeJSON) {
            headers["Content-Type"] = "application/json";
        }

        const token = sessionStorage.getItem("dockgo_token");
        if (token && !state.isLoggedIn) {
            headers["Authorization"] = `Bearer ${token}`;
        }
        if (state.isLoggedIn) {
            headers["X-CSRF-Token"] = getCsrfToken();
        }
        return headers;
    };

    const withAgentQuery = (url) => {
        if (!state.currentAgentID) return url;
        const sep = url.includes("?") ? "&" : "?";
        return `${url}${sep}agent=${encodeURIComponent(state.currentAgentID)}`;
    };

    const showLoginModal = () => {
        if (!loginModal) return;
        loginModal.classList.remove("hidden");
        if (loginUsernameInput) loginUsernameInput.focus();
    };

    const hideLoginModal = () => {
        if (!loginModal) return;
        loginModal.classList.add("hidden");
        if (loginError) loginError.classList.add("hidden");
        if (loginForm) loginForm.reset();
    };

    const showNoAuthModal = () => {
        if (noAuthModal) noAuthModal.classList.remove("hidden");
    };

    const setLogoutVisible = (visible) => {
        [logoutBtn, logoutAllBtn].forEach((button) => {
            if (!button) return;
            button.classList.toggle("hidden", !visible);
        });
    };

    const checkAuthStatus = async () => {
        try {
            const response = await fetch("/api/me");
            if (!response.ok) return;
            const data = await response.json();
            state.isLoggedIn = !!data.logged_in;
            state.authEnabled = !!data.user_auth_enabled;
            state.apiTokenEnabled = !!data.api_token_enabled;
            setLogoutVisible(state.isLoggedIn);

            if (!state.authEnabled && !state.apiTokenEnabled) {
                showNoAuthModal();
            }
        } catch (error) {
            console.error("Auth check failed", error);
        }
    };

    const updateHostSelector = (agents) => {
        if (!hostSelector) return;
        const previous = hostSelector.value;
        hostSelector.innerHTML = "";

        const localOption = document.createElement("option");
        localOption.value = "";
        localOption.textContent = "Local host";
        hostSelector.appendChild(localOption);

        agents.forEach((agent) => {
            const option = document.createElement("option");
            option.value = agent.id;
            const status = agent.status === "online" ? "●" : "○";
            option.textContent = `${status} ${agent.name}`;
            hostSelector.appendChild(option);
        });

        if (previous && agents.some((agent) => agent.id === previous)) {
            hostSelector.value = previous;
        } else {
            hostSelector.value =
                state.currentAgentID &&
                agents.some((agent) => agent.id === state.currentAgentID)
                    ? state.currentAgentID
                    : "";
        }
    };

    const fetchAgents = async () => {
        try {
            const response = await fetch("/api/agents", {
                headers: getAuthHeaders(),
            });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();
            const agents = Array.isArray(data)
                ? data
                : data && Array.isArray(data.agents)
                  ? data.agents
                  : [];
            updateHostSelector(agents);
        } catch (error) {
            console.error("Failed to fetch agents", error);
            updateHostSelector([]);
        }
    };

    const fetchVersion = async () => {
        try {
            const response = await fetch("/api/health");
            if (!response.ok) return;
            const data = await response.json();
            const el = document.getElementById("app-version");
            if (el && data.version) el.textContent = "v" + data.version;
        } catch (error) {
            console.error("Failed to fetch health/version", error);
        }
    };

    if (loginForm) {
        loginForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            const username = loginUsernameInput.value;
            const password = loginPasswordInput.value;

            try {
                const response = await fetch("/api/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password }),
                });

                if (!response.ok) {
                    loginError.textContent = "Invalid credentials";
                    loginError.classList.remove("hidden");
                    return;
                }

                hideLoginModal();
                await checkAuthStatus();
                await fetchAgents();
                if (callbacks.onLogin) callbacks.onLogin();
            } catch (error) {
                loginError.textContent = "Login failed: " + error.message;
                loginError.classList.remove("hidden");
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to logout?")) return;
            try {
                await fetch("/api/logout", {
                    method: "POST",
                    headers: { "X-CSRF-Token": getCsrfToken() },
                });
            } finally {
                window.location.reload();
            }
        });
    }

    if (logoutAllBtn) {
        logoutAllBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to logout ALL devices?")) {
                return;
            }
            try {
                await fetch("/api/logout-all", {
                    method: "POST",
                    headers: { "X-CSRF-Token": getCsrfToken() },
                });
            } finally {
                window.location.reload();
            }
        });
    }

    if (hostSelector) {
        hostSelector.addEventListener("change", () => {
            state.currentAgentID = hostSelector.value;
            if (state.currentAgentID) {
                localStorage.setItem("dockgo_agent_id", state.currentAgentID);
            } else {
                localStorage.removeItem("dockgo_agent_id");
            }
            if (callbacks.onHostChange) callbacks.onHostChange();
        });
    }

    const init = async (options = {}) => {
        callbacks = options;
        await checkAuthStatus();
        fetchVersion();
        await fetchAgents();

        if (state.authEnabled && !state.isLoggedIn) {
            showLoginModal();
            return;
        }
        if (!state.authEnabled && !state.apiTokenEnabled) {
            return;
        }
        if (callbacks.onReady) callbacks.onReady();
    };

    const formatBytes = (bytes) => {
        if (!Number.isFinite(bytes) || bytes < 0) return "-";
        if (bytes === 0) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.min(
            Math.floor(Math.log(bytes) / Math.log(1024)),
            units.length - 1,
        );
        return `${parseFloat((bytes / 1024 ** i).toFixed(2))} ${units[i]}`;
    };

    // Compact form used inside dense tables: 126K, 241.6M, 3.1G.
    const formatBytesCompact = (bytes) => {
        if (!Number.isFinite(bytes) || bytes < 0) return "-";
        if (bytes < 1024) return `${Math.round(bytes)}B`;

        const units = ["K", "M", "G", "T", "P"];
        let value = bytes / 1024;
        let unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value /= 1024;
            unit++;
        }
        if (unit === 0) return `${Math.round(value)}K`;
        return `${parseFloat(value.toFixed(1))}${units[unit]}`;
    };

    // Accepts Unix seconds (Docker images) or an RFC3339 string (volumes).
    const formatDate = (value) => {
        if (!value) return "-";
        const date =
            typeof value === "number" ? new Date(value * 1000) : new Date(value);
        if (Number.isNaN(date.getTime())) return "-";

        const pad = (n) => String(n).padStart(2, "0");
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
    };

    // Shared client-side sorter for the resource tables. Pages supply a value
    // extractor so each column can define how it compares.
    const createTableSorter = (onSort, options = {}) => {
        let sortKey = options.key || "name";
        let sortDir = options.dir || 1;
        const buttons = document.querySelectorAll(".sort-btn");

        const updateArrows = () => {
            buttons.forEach((button) => {
                const arrow = button.querySelector(".sort-arrow");
                if (!arrow) return;
                if (button.dataset.sort === sortKey) {
                    arrow.textContent = sortDir === 1 ? "↑" : "↓";
                } else {
                    arrow.textContent = "↕";
                }
            });
        };

        const sort = (rows, valueOf) =>
            rows.slice().sort((a, b) => {
                const left = valueOf(a, sortKey);
                const right = valueOf(b, sortKey);
                if (typeof left === "number" && typeof right === "number") {
                    return (left - right) * sortDir;
                }
                return (
                    String(left).localeCompare(String(right)) * sortDir
                );
            });

        buttons.forEach((button) => {
            button.addEventListener("click", () => {
                const key = button.dataset.sort;
                if (sortKey === key) {
                    sortDir = -sortDir;
                } else {
                    sortKey = key;
                    sortDir = 1;
                }
                updateArrows();
                if (onSort) onSort();
            });
        });
        updateArrows();

        return {
            sort,
            updateArrows,
            getKey: () => sortKey,
            getDir: () => sortDir,
        };
    };

    // Start/stop button used next to container state badges. The caller decides
    // how to refresh and where to surface errors.
    const createContainerActionButton = ({ name, state: containerState, onDone, onError } = {}) => {
        const running = containerState === "running";
        const action = running ? "stop" : "start";
        const button = document.createElement("button");
        button.type = "button";
        button.className = `container-action-btn ${action}`;
        button.title = running ? "Stop container" : "Start container";
        button.setAttribute(
            "aria-label",
            `${running ? "Stop" : "Start"} ${name}`,
        );
        button.innerHTML = running
            ? '<span class="nf nf-stop" aria-hidden="true"></span>'
            : '<span class="nf nf-play" aria-hidden="true"></span>';

        button.addEventListener("click", async (event) => {
            event.stopPropagation();
            button.disabled = true;
            try {
                const response = await fetch(
                    withAgentQuery(
                        `/api/container/${encodeURIComponent(name)}/action`,
                    ),
                    {
                        method: "POST",
                        headers: getAuthHeaders(true),
                        body: JSON.stringify({ action }),
                    },
                );

                if (response.status === 401 || response.status === 403) {
                    if (state.authEnabled) showLoginModal();
                    throw new Error("Authentication required");
                }
                if (!response.ok) {
                    let message = "";
                    try {
                        const data = await response.json();
                        message = data.error || "";
                    } catch (parseError) {
                        console.error("Invalid action response", parseError);
                    }
                    throw new Error(message || `HTTP ${response.status}`);
                }

                if (onDone) onDone();
            } catch (error) {
                console.error(`Failed to ${action} ${name}:`, error);
                if (onError) onError(`Failed to ${action} ${name}: ${error.message}`);
            } finally {
                button.disabled = false;
            }
        });

        return button;
    };

    // Shows the shared confirmation modal. Falls back to the native dialog on
    // pages that do not include the modal markup.
    const showConfirmModal = ({
        title = "Confirm",
        message,
        confirmLabel = "OK",
        danger = false,
    } = {}) => {
        return new Promise((resolve) => {
            if (
                !confirmModal ||
                !confirmTitleEl ||
                !confirmMessageEl ||
                !confirmCancelBtn ||
                !confirmOkBtn
            ) {
                resolve(window.confirm(message));
                return;
            }

            const previousFocus = document.activeElement;

            confirmTitleEl.textContent = title;
            confirmMessageEl.textContent = message;
            confirmOkBtn.textContent = confirmLabel;
            confirmOkBtn.classList.toggle("danger", danger);
            confirmOkBtn.classList.toggle("primary", !danger);
            confirmModal.classList.remove("hidden");
            confirmCancelBtn.focus();

            const cleanup = () => {
                confirmModal.classList.add("hidden");
                confirmOkBtn.removeEventListener("click", onConfirm);
                confirmCancelBtn.removeEventListener("click", onCancel);
                confirmModal.removeEventListener("click", onOverlayClick);
                document.removeEventListener("keydown", onKeyDown);
                confirmOkBtn.classList.add("primary");
                confirmOkBtn.classList.remove("danger");
                confirmTitleEl.textContent = "Confirm";
                if (previousFocus && typeof previousFocus.focus === "function") {
                    previousFocus.focus();
                }
            };

            const finish = (confirmed) => {
                cleanup();
                resolve(confirmed);
            };

            const onConfirm = () => finish(true);
            const onCancel = () => finish(false);
            const onOverlayClick = (event) => {
                if (event.target === confirmModal) finish(false);
            };
            const onKeyDown = (event) => {
                if (event.key === "Escape") {
                    event.preventDefault();
                    finish(false);
                }
            };

            confirmOkBtn.addEventListener("click", onConfirm);
            confirmCancelBtn.addEventListener("click", onCancel);
            confirmModal.addEventListener("click", onOverlayClick);
            document.addEventListener("keydown", onKeyDown);
        });
    };

    // Adds a "Toggle columns" dropdown to a table's panel header. Visibility is
    // persisted per table and reapplied whenever rows are re-rendered.
    const createColumnToggle = ({ tableSelector, storageKey } = {}) => {
        const table = document.querySelector(tableSelector);
        if (!table || !table.tHead) return null;
        const panel = table.closest(".stack-panel");
        const actions = panel
            ? panel.querySelector(".stack-panel-actions")
            : null;
        if (!actions) return null;

        const headerCells = Array.from(table.tHead.rows[0].cells);
        const columns = headerCells
            .map((cell, index) => ({
                key: cell.dataset.column || `column-${index}`,
                label: (cell.textContent || "")
                    .replace(/[↕↑↓]/g, "")
                    .trim(),
            }))
            .filter((column) => column.label);

        let hidden = new Set();
        try {
            const stored = JSON.parse(
                localStorage.getItem(storageKey) || "[]",
            );
            if (Array.isArray(stored)) {
                hidden = new Set(stored);
            }
        } catch (error) {
            console.error("Failed to read column preferences", error);
        }

        const menu = document.createElement("div");
        menu.className = "menu column-menu";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn secondary column-menu-btn";
        button.textContent = "Columns";

        const dropdown = document.createElement("div");
        dropdown.className = "menu-dropdown column-menu-dropdown hidden";

        const title = document.createElement("div");
        title.className = "column-menu-title";
        title.textContent = "Toggle columns";
        dropdown.appendChild(title);

        const apply = () => {
            const keys = headerCells.map(
                (cell, index) => cell.dataset.column || `column-${index}`,
            );
            table.querySelectorAll("tbody tr").forEach((row) => {
                if (row.dataset.detailRow === "true") return;
                Array.from(row.cells).forEach((cell, index) => {
                    if (keys[index]) cell.dataset.column = keys[index];
                });
            });

            headerCells.forEach((cell, index) => {
                const key = keys[index];
                const isHidden = hidden.has(key);
                cell.style.display = isHidden ? "none" : "";
                table.querySelectorAll("tbody tr").forEach((row) => {
                    if (row.dataset.detailRow === "true") return;
                    const bodyCell = row.cells[index];
                    if (bodyCell) {
                        bodyCell.style.display = isHidden ? "none" : "";
                    }
                });
            });
        };

        const persist = () => {
            try {
                localStorage.setItem(
                    storageKey,
                    JSON.stringify(Array.from(hidden)),
                );
            } catch (error) {
                console.error("Failed to save column preferences", error);
            }
        };

        columns.forEach((column) => {
            const option = document.createElement("label");
            option.className = "column-option";

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.checked = !hidden.has(column.key);
            checkbox.addEventListener("change", () => {
                if (!checkbox.checked) {
                    if (hidden.size >= columns.length - 1) {
                        checkbox.checked = true;
                        return;
                    }
                    hidden.add(column.key);
                } else {
                    hidden.delete(column.key);
                }
                persist();
                apply();
            });

            const text = document.createElement("span");
            text.textContent = column.label;

            option.append(checkbox, text);
            dropdown.appendChild(option);
        });

        button.addEventListener("click", (event) => {
            event.stopPropagation();
            dropdown.classList.toggle("hidden");
        });
        dropdown.addEventListener("click", (event) => event.stopPropagation());
        document.addEventListener("click", () => {
            dropdown.classList.add("hidden");
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                dropdown.classList.add("hidden");
            }
        });

        menu.append(button, dropdown);
        actions.insertBefore(menu, actions.firstChild);

        const observer = new MutationObserver(() => apply());
        observer.observe(table, {
            childList: true,
            subtree: true,
        });
        apply();

        return { apply };
    };

    // Adds client-side pagination below a table. Controls only appear when the
    // row count exceeds the page size.
    const createPager = ({ tableSelector, pageSize = 25, onChange } = {}) => {
        const table = document.querySelector(tableSelector);
        const wrapper = table ? table.closest(".data-table-wrapper") : null;
        if (!wrapper) return null;

        const pager = document.createElement("div");
        pager.className = "pagination hidden";

        const info = document.createElement("span");
        info.className = "pagination-info";

        const actions = document.createElement("div");
        actions.className = "pagination-actions";

        const prev = document.createElement("button");
        prev.type = "button";
        prev.className = "btn secondary pagination-btn";
        prev.textContent = "Prev";

        const pageLabel = document.createElement("span");
        pageLabel.className = "pagination-page";

        const next = document.createElement("button");
        next.type = "button";
        next.className = "btn secondary pagination-btn";
        next.textContent = "Next";

        actions.append(prev, pageLabel, next);
        pager.append(info, actions);
        wrapper.insertAdjacentElement("afterend", pager);

        let current = 1;
        let pageCount = 1;

        const render = (total) => {
            pageCount = Math.max(1, Math.ceil(total / pageSize));
            if (current > pageCount) current = pageCount;
            if (current < 1) current = 1;

            const visible = total > pageSize;
            pager.classList.toggle("hidden", !visible);
            if (!visible) return;

            const start = (current - 1) * pageSize + 1;
            const end = Math.min(total, current * pageSize);
            info.textContent = `${start}–${end} of ${total}`;
            pageLabel.textContent = `Page ${current} of ${pageCount}`;
            prev.disabled = current <= 1;
            next.disabled = current >= pageCount;
        };

        const setPage = (value) => {
            current = value;
            if (onChange) onChange();
        };

        prev.addEventListener("click", () => {
            if (current > 1) setPage(current - 1);
        });
        next.addEventListener("click", () => {
            if (current < pageCount) setPage(current + 1);
        });

        render(0);

        return {
            slice: (rows) =>
                rows.slice((current - 1) * pageSize, current * pageSize),
            render,
            reset: () => {
                current = 1;
            },
            getPage: () => current,
        };
    };

    window.DockGoPage = {
        init,
        getAuthHeaders,
        withAgentQuery,
        getState: () => ({ ...state }),
        refreshAgents: fetchAgents,
        showLoginModal,
        showConfirmModal,
        formatBytes,
        formatBytesCompact,
        formatDate,
        createTableSorter,
        createContainerActionButton,
        createColumnToggle,
        createPager,
    };
})();

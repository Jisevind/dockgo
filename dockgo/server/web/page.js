/* Shared page chrome for standalone DockGo pages.
 *
 * Owns authentication state, the login/no-auth modals, logout controls, the
 * host selector, and the API headers/URL helpers those controls need. The
 * dashboard still uses app.js until it is migrated to its own page.
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

    const state = {
        currentAgentID: localStorage.getItem("dockgo_agent_id") || "",
        isLoggedIn: false,
        authEnabled: false,
        apiTokenEnabled: false,
    };

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
            const agents = await response.json();
            updateHostSelector(Array.isArray(agents) ? agents : []);
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

    window.DockGoPage = {
        init,
        getAuthHeaders,
        withAgentQuery,
        getState: () => ({ ...state }),
        showLoginModal,
        formatBytes,
        formatBytesCompact,
        formatDate,
    };
})();

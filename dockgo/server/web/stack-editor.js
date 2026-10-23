/* Stack file editor page: edit compose and env files for one stack. */
/* eslint-env browser */
document.addEventListener("DOMContentLoaded", () => {
    const titleEl = document.getElementById("editor-title");
    const subtitleEl = document.getElementById("editor-subtitle");
    const errorEl = document.getElementById("editor-error");
    const loadingEl = document.getElementById("editor-loading");
    const contentEl = document.getElementById("editor-content");
    const warningEl = document.getElementById("file-editor-warning");
    const fileSelect = document.getElementById("file-select");
    const fileSelectBtn = document.getElementById("file-select-btn");
    const fileSelectLabel = document.getElementById("file-select-label");
    const fileSelectMenu = document.getElementById("file-select-menu");
    const addEnvBtn = document.getElementById("add-env-file-btn");
    const addEnvForm = document.getElementById("add-env-form");
    const addEnvName = document.getElementById("add-env-name");
    const addEnvCreateBtn = document.getElementById("add-env-create-btn");
    const addEnvCancelBtn = document.getElementById("add-env-cancel-btn");
    const textEl = document.getElementById("file-editor-text");
    const statusEl = document.getElementById("file-editor-status");
    const revertBtn = document.getElementById("file-editor-revert-btn");
    const saveBtn = document.getElementById("file-editor-save-btn");
    const saveDeployBtn = document.getElementById(
        "file-editor-save-deploy-btn",
    );
    const refreshBtn = document.getElementById("refresh-stack-editor-btn");

    const page = window.DockGoPage;
    const VALIDATE_DEBOUNCE_MS = 400;

    const state = {
        stack: null,
        targets: [],
        index: 0,
        original: "",
        dirty: false,
        busy: false,
        valid: true,
        validateTimer: null,
        validateAbort: null,
    };

    const stackId = () => {
        const match = window.location.pathname.match(/^\/stacks\/([^/]+)\/files\/?$/);
        return match ? decodeURIComponent(match[1]) : "";
    };

    const stackApiUrl = (suffix = "") =>
        page.withAgentQuery(
            `/api/stacks/${encodeURIComponent(stackId())}${suffix}`,
        );

    const baseUrl = () => stackApiUrl();

    const fileUrl = (target) =>
        page.withAgentQuery(
            `/api/stacks/${encodeURIComponent(stackId())}/file?kind=` +
                `${encodeURIComponent(target.kind)}&index=${encodeURIComponent(target.index)}`,
        );

    const validateUrl = (target) =>
        page.withAgentQuery(
            `/api/stacks/${encodeURIComponent(stackId())}/file/validate?kind=` +
                `${encodeURIComponent(target.kind)}&index=${encodeURIComponent(target.index)}`,
        );

    const currentTarget = () => state.targets[state.index] || null;

    const setStatus = (message, kind = "") => {
        statusEl.textContent = message;
        statusEl.className = "file-editor-status";
        if (kind) statusEl.classList.add(kind);
    };

    const setError = (message) => {
        loadingEl.classList.add("hidden");
        contentEl.classList.add("hidden");
        errorEl.textContent = message;
        errorEl.classList.remove("hidden");
    };

    const setBusy = (busy) => {
        state.busy = busy;
        textEl.disabled = busy;
        fileSelectBtn.disabled = busy;
        updateButtons();
    };

    const updateButtons = () => {
        const target = currentTarget();
        const blocked = !target || target.editable === false;
        textEl.disabled = state.busy || blocked;
        fileSelectBtn.disabled = state.busy;
        if (state.busy) closeFileSelect();
        revertBtn.disabled = state.busy || blocked || !state.dirty;
        saveBtn.disabled =
            state.busy ||
            blocked ||
            !state.dirty ||
            state.valid === false;
        // Save & deploy remains available without edits so a failed deploy can
        // be retried against the current saved file.
        saveDeployBtn.disabled =
            state.busy || blocked || state.valid === false;
    };

    const applyWarning = () => {
        const messages = [];
        if (state.stack && state.stack.kind === "git_repo") {
            messages.push(
                "This stack is tracked from a git repository. Saving edits the " +
                    "checked-out working copy, and a later git pull may overwrite your changes.",
            );
        }
        const target = currentTarget();
        if (target && target.editable === false) {
            messages.push(
                "This file cannot be edited: it is missing, or it is outside the " +
                    "allowed compose paths for its host.",
            );
        }
        warningEl.textContent = messages.join(" ");
        warningEl.classList.toggle("hidden", messages.length === 0);
    };

    const targetLabel = (target) => {
        let label = target.label || `${target.kind} ${target.index}`;
        if (target.kind === "env") label += " (env)";
        if (target.exists === false) label += " — missing";
        if (target.editable === false) label += " — not editable";
        return label;
    };

    const closeFileSelect = () => {
        fileSelectMenu.classList.add("hidden");
        fileSelectBtn.setAttribute("aria-expanded", "false");
    };

    const updateFileSelectLabel = () => {
        const target = currentTarget();
        fileSelectLabel.textContent = target
            ? targetLabel(target)
            : "Choose a file";
    };

    const renderTargets = () => {
        fileSelectMenu.textContent = "";
        state.targets.forEach((target, index) => {
            const option = document.createElement("button");
            option.type = "button";
            option.className = "file-select-option";
            option.setAttribute("role", "option");
            option.setAttribute(
                "aria-selected",
                index === state.index ? "true" : "false",
            );
            if (index === state.index) option.classList.add("selected");
            option.textContent = targetLabel(target);
            option.addEventListener("click", () => selectTarget(index));
            fileSelectMenu.appendChild(option);
        });
        updateFileSelectLabel();
    };

    const renderValidation = (result) => {
        if (!result || result.valid) {
            state.valid = true;
            setStatus("Valid.", "success");
            return;
        }
        state.valid = false;
        const errors = Array.isArray(result.errors) ? result.errors : [];
        const first = errors[0];
        const detail = first
            ? `line ${first.line}, column ${first.column}: ${first.message}`
            : "invalid syntax";
        const more = errors.length > 1 ? ` (+${errors.length - 1} more)` : "";
        setStatus(`Invalid — ${detail}${more}`, "error");
    };

    const validateDraft = async () => {
        const target = currentTarget();
        if (!target || target.editable === false) return;

        if (state.validateAbort) state.validateAbort.abort();
        const controller = new AbortController();
        state.validateAbort = controller;
        const content = textEl.value;

        try {
            const response = await fetch(validateUrl(target), {
                method: "POST",
                headers: page.getAuthHeaders(true),
                body: JSON.stringify({ content }),
                signal: controller.signal,
            });
            const data = await response.json().catch(() => ({}));
            if (controller.signal.aborted) return;
            if (!response.ok) {
                throw new Error(
                    data.error || `Validation failed (${response.status})`,
                );
            }
            if (content !== textEl.value) return;
            renderValidation(data);
            updateButtons();
        } catch (error) {
            if (error.name === "AbortError") return;
            setStatus(`Validation failed: ${error.message}`, "error");
        }
    };

    const scheduleValidation = (immediate = false) => {
        if (state.validateTimer) clearTimeout(state.validateTimer);
        state.validateTimer = null;
        if (immediate) {
            validateDraft();
            return;
        }
        setStatus("Checking…");
        state.validateTimer = setTimeout(
            validateDraft,
            VALIDATE_DEBOUNCE_MS,
        );
    };

    const loadTarget = async (index) => {
        state.index = Number(index);
        closeFileSelect();
        renderTargets();
        const target = currentTarget();
        applyWarning();
        if (!target) return;

        if (target.editable === false) {
            textEl.value = "";
            state.original = "";
            state.dirty = false;
            state.valid = true;
            setStatus("This file cannot be edited.", "error");
            updateButtons();
            return;
        }

        setBusy(true);
        setStatus("Loading…");
        try {
            const response = await fetch(fileUrl(target), {
                headers: page.getAuthHeaders(),
            });
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(
                    data.error || `Failed to read file (${response.status})`,
                );
            }
            textEl.value = data.content || "";
            state.original = data.content || "";
            state.dirty = false;
            state.valid = true;
            setStatus("Loaded.");
            scheduleValidation(true);
        } catch (error) {
            setStatus(`Failed to read file: ${error.message}`, "error");
        } finally {
            setBusy(false);
        }
    };

    const persistFile = async (target) => {
        try {
            const response = await fetch(fileUrl(target), {
                method: "PUT",
                headers: page.getAuthHeaders(true),
                body: JSON.stringify({ content: textEl.value }),
            });
            const data = await response.json().catch(() => ({}));

            if (response.ok) {
                state.original = textEl.value;
                state.dirty = false;
                state.valid = true;
                updateButtons();
                return true;
            }

            const issues = [];
            if (data.syntax && Array.isArray(data.syntax.errors)) {
                data.syntax.errors.forEach((err) =>
                    issues.push(`line ${err.line}: ${err.message}`),
                );
            }
            if (data.validation && Array.isArray(data.validation.issues)) {
                issues.push(...data.validation.issues);
            }
            const detail = issues.length ? `\n${issues.join("\n")}` : "";
            let restoreNote = "";
            if (data.rolled_back === true) {
                restoreNote = " The previous content was restored.";
            } else if (data.rolled_back === false) {
                restoreNote =
                    " WARNING: the previous content could NOT be restored, so the " +
                    "file may be left in an invalid state on its host.";
            }
            setStatus(
                (data.error || "Save failed.") + restoreNote + detail,
                "error",
            );
            return false;
        } catch (error) {
            setStatus(`Save failed: ${error.message}`, "error");
            return false;
        }
    };

    const deployStack = async () => {
        const response = await fetch(
            page.withAgentQuery(
                `/api/stacks/${encodeURIComponent(stackId())}/deploy`,
            ),
            {
                method: "POST",
                headers: page.getAuthHeaders(),
            },
        );

        if (response.status === 401 || response.status === 403) {
            if (page.getState().authEnabled) page.showLoginModal();
            throw new Error("Authentication required");
        }
        if (!response.ok) {
            let message = `Deploy failed (${response.status})`;
            try {
                const data = await response.json();
                message = data.error || message;
            } catch (error) {
                /* keep the status-based fallback */
            }
            throw new Error(message);
        }
        if (!response.body) {
            throw new Error("Deploy stream is unavailable.");
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let done = false;

        const processEvent = (data) => {
            if (data.type === "start" || data.type === "progress") {
                setStatus(data.message || data.status || "Deploying…");
            } else if (data.type === "error") {
                throw new Error(data.error || "Stack deployment failed.");
            } else if (data.type === "done") {
                done = true;
            }
        };

        while (true) {
            const { value, done: streamDone } = await reader.read();
            if (streamDone) break;
            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split("\n\n");
            buffer = parts.pop() || "";
            for (const part of parts) {
                for (const line of part.split("\n")) {
                    if (!line.startsWith("data: ")) continue;
                    try {
                        processEvent(JSON.parse(line.slice(6)));
                    } catch (error) {
                        if (error instanceof SyntaxError) {
                            console.error("Deploy stream parse error", error);
                            continue;
                        }
                        throw error;
                    }
                }
            }
        }

        if (!done) {
            throw new Error("Deploy stream ended before completion.");
        }
    };

    const saveFile = async (deploy = false) => {
        const target = currentTarget();
        if (!target || target.editable === false) return;

        setBusy(true);
        setStatus("Saving…");
        const saved = await persistFile(target);
        if (saved) {
            if (deploy) {
                setStatus("Deploying…");
                try {
                    await deployStack();
                    setStatus("Deployed successfully.", "success");
                } catch (error) {
                    setStatus(`Deploy failed: ${error.message}`, "error");
                }
            } else {
                setStatus("Saved.", "success");
            }
        }
        setBusy(false);
    };

    const updateEnvControls = () => {
        const hasExistingEnv = state.targets.some(
            (target) => target.kind === "env" && target.exists !== false,
        );
        const missingEnv = state.targets.find(
            (target) => target.kind === "env" && target.exists === false,
        );
        addEnvBtn.classList.toggle("hidden", hasExistingEnv);
        addEnvName.value = missingEnv ? missingEnv.label : ".env";
        addEnvForm.classList.add("hidden");
    };

    const createEnvFile = async () => {
        const name = addEnvName.value.trim();
        if (!name) {
            setStatus("Env file name is required.", "error");
            return;
        }
        if (
            state.dirty &&
            !window.confirm(
                "Discard unsaved changes and create the env file?",
            )
        ) {
            return;
        }

        addEnvCreateBtn.disabled = true;
        setStatus("Creating env file…");
        try {
            const response = await fetch(stackApiUrl("/env-file"), {
                method: "POST",
                headers: page.getAuthHeaders(true),
                body: JSON.stringify({ name }),
            });
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                throw new Error("Authentication required");
            }
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(
                    data.error || `Failed to create env file (${response.status})`,
                );
            }
            addEnvForm.classList.add("hidden");
            await loadEditor(name);
        } catch (error) {
            setStatus(`Failed to create env file: ${error.message}`, "error");
        } finally {
            addEnvCreateBtn.disabled = false;
        }
    };

    const loadEditor = async (selectEnvName = "") => {
        const id = stackId();
        if (!id) {
            setError("No stack id was provided.");
            return;
        }
        if (!page) {
            setError("The page failed to initialize.");
            return;
        }

        errorEl.classList.add("hidden");
        contentEl.classList.add("hidden");
        loadingEl.classList.remove("hidden");
        loadingEl.textContent = "Loading stack files...";

        try {
            const response = await fetch(baseUrl(), {
                headers: page.getAuthHeaders(),
            });
            if (response.status === 404) {
                setError("Stack not found.");
                return;
            }
            if (response.status === 401 || response.status === 403) {
                if (page.getState().authEnabled) page.showLoginModal();
                setError("Authentication required to edit this stack.");
                return;
            }
            const detail = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(
                    detail.error || `Failed to load stack (${response.status})`,
                );
            }

            state.stack = detail.stack || null;
            if (!state.stack) throw new Error("Stack details are missing.");

            titleEl.textContent = `Edit Stack: ${state.stack.name}`;
            subtitleEl.textContent =
                state.stack.working_dir ||
                "Compose and env files for this registered stack.";

            const filesResponse = await fetch(stackApiUrl("/files"), {
                headers: page.getAuthHeaders(),
            });
            const filesData = await filesResponse.json().catch(() => ({}));
            if (!filesResponse.ok) {
                throw new Error(
                    filesData.error ||
                        `Failed to list files (${filesResponse.status})`,
                );
            }
            state.targets = Array.isArray(filesData.files)
                ? filesData.files
                : [];
            if (state.targets.length === 0) {
                throw new Error("This stack has no editable files.");
            }

            let initialIndex = 0;
            if (selectEnvName) {
                const envIndex = state.targets.findIndex(
                    (target) =>
                        target.kind === "env" &&
                        target.label === selectEnvName,
                );
                if (envIndex >= 0) initialIndex = envIndex;
            }
            state.index = initialIndex;
            state.original = "";
            state.dirty = false;
            state.valid = true;
            renderTargets();
            updateEnvControls();
            applyWarning();
            updateButtons();

            loadingEl.classList.add("hidden");
            contentEl.classList.remove("hidden");
            await loadTarget(initialIndex);
        } catch (error) {
            console.error("Failed to load stack files:", error);
            setError(`Failed to load stack files: ${error.message}`);
        }
    };

    const selectTarget = async (nextIndex) => {
        if (nextIndex === state.index) {
            closeFileSelect();
            return;
        }
        if (state.dirty && !window.confirm("Discard unsaved changes?")) {
            closeFileSelect();
            return;
        }
        await loadTarget(nextIndex);
    };

    fileSelectBtn.addEventListener("click", () => {
        const isOpen = !fileSelectMenu.classList.contains("hidden");
        if (isOpen) {
            closeFileSelect();
        } else {
            fileSelectMenu.classList.remove("hidden");
            fileSelectBtn.setAttribute("aria-expanded", "true");
        }
    });

    document.addEventListener("click", (event) => {
        if (!fileSelect.contains(event.target)) closeFileSelect();
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeFileSelect();
    });

    textEl.addEventListener("input", () => {
        state.dirty = textEl.value !== state.original;
        updateButtons();
        if (currentTarget() && currentTarget().editable !== false) {
            scheduleValidation();
        }
    });

    revertBtn.addEventListener("click", () => {
        textEl.value = state.original;
        state.dirty = false;
        state.valid = true;
        setStatus("Reverted.");
        updateButtons();
        scheduleValidation();
    });

    saveBtn.addEventListener("click", () => saveFile(false));
    saveDeployBtn.addEventListener("click", () => saveFile(true));

    addEnvBtn.addEventListener("click", () => {
        addEnvForm.classList.remove("hidden");
        addEnvName.focus();
        addEnvName.select();
    });
    addEnvCancelBtn.addEventListener("click", () => {
        addEnvForm.classList.add("hidden");
    });
    addEnvCreateBtn.addEventListener("click", createEnvFile);
    addEnvName.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            event.preventDefault();
            createEnvFile();
        }
    });

    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            if (
                state.dirty &&
                !window.confirm("Discard unsaved changes and reload?")
            ) {
                return;
            }
            loadEditor();
        });
    }

    window.addEventListener("beforeunload", (event) => {
        if (!state.dirty) return;
        event.preventDefault();
        event.returnValue = "";
    });

    if (page) {
        page.init({
            onReady: loadEditor,
            onLogin: loadEditor,
            onHostChange: loadEditor,
        });
    }
});

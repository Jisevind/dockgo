/* Collapsible primary navigation for narrow screens.
 *
 * On wide screens the sidebar is always visible and the toggle is hidden by
 * CSS. On narrow screens the navigation folds behind a toggle button that
 * shows the current page name. The collapsed state only applies once this
 * script has run, so navigation stays usable without JavaScript.
 */
/* eslint-env browser */
(() => {
    const sidebar = document.querySelector(".sidebar");
    const toggle = sidebar?.querySelector(".sidebar-toggle");
    const nav = sidebar?.querySelector(".sidebar-nav");
    if (!sidebar || !toggle || !nav) return;

    const label = toggle.querySelector(".sidebar-toggle-label");
    const updateLabel = () => {
        const active = nav.querySelector(".sidebar-link.active");
        if (label && active) label.textContent = active.textContent.trim();
    };
    updateLabel();

    // app.js switches the active link in place; keep the label in sync.
    new MutationObserver(updateLabel).observe(nav, {
        subtree: true,
        attributes: true,
        attributeFilter: ["class"],
    });

    const setOpen = (open) => {
        sidebar.classList.toggle("open", open);
        toggle.setAttribute("aria-expanded", String(open));
    };

    sidebar.classList.add("sidebar-collapsible");
    setOpen(false);

    toggle.addEventListener("click", () => {
        setOpen(!sidebar.classList.contains("open"));
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && sidebar.classList.contains("open")) {
            setOpen(false);
            toggle.focus();
        }
    });

    // Close when a link is chosen (covers in-page navigation in app.js).
    nav.addEventListener("click", (event) => {
        if (event.target.closest(".sidebar-link")) setOpen(false);
    });
})();

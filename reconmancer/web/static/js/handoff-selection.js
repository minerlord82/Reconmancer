(() => {
    "use strict";

    const match = window.location.pathname.match(/^\/p\/([^/]+)\//);
    if (!match) return;
    const slug = match[1];

    let profiles = [];
    const profileNode = document.getElementById("reconmancer-auth-profiles");
    if (profileNode) {
        try { profiles = JSON.parse(profileNode.textContent || "[]"); }
        catch (_) { profiles = []; }
    }

    const rows = Array.from(document.querySelectorAll("tr[data-recon-source-engine][data-recon-run-id][data-recon-record-id]"));


    function templateSourceOptions() {
        return `
            <option value="default">Default Nuclei</option>
            <option value="projectdiscovery">nuclei-templates (ProjectDiscovery)</option>
        `;
    }

    function bindTemplateSource(form) {
        const destination = form.querySelector('select[name="destination_engine"]');
        const templateSource = form.querySelector('select[name="template_source"]');
        if (!destination || !templateSource) return;

        const sync = () => {
            const show = destination.value === "nuclei";
            templateSource.hidden = !show;
            templateSource.disabled = !show;
        };

        destination.addEventListener("change", sync);
        sync();
    }

    function profileOptions() {
        let html = '<option value="">Anonymous</option>';
        for (const p of profiles) {
            const name = String(p.name || p.id || "Auth profile");
            html += `<option value="${String(p.id).replaceAll('"','&quot;')}">${name}</option>`;
        }
        return html;
    }

    if (rows.length) {
        for (const row of rows) {
            const cell = document.createElement("td");
            cell.className = "handoff-select-cell";
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.className = "handoff-row-checkbox";
            checkbox.value = `${row.dataset.reconSourceEngine}|${row.dataset.reconRunId}|${row.dataset.reconRecordId}`;
            checkbox.addEventListener("change", updateToolbar);
            cell.appendChild(checkbox);
            row.insertBefore(cell, row.firstElementChild);
        }

        for (const table of document.querySelectorAll("table.data-table")) {
            const marked = table.querySelector("tr[data-recon-source-engine]");
            if (!marked) continue;
            const header = table.querySelector("thead tr");
            if (header && !header.querySelector(".handoff-select-heading")) {
                const th = document.createElement("th");
                th.className = "handoff-select-heading";
                const toggle = document.createElement("input");
                toggle.type = "checkbox";
                toggle.title = "Select this table";
                toggle.addEventListener("change", () => {
                    for (const cb of table.querySelectorAll(".handoff-row-checkbox")) cb.checked = toggle.checked;
                    updateToolbar();
                });
                th.appendChild(toggle);
                header.insertBefore(th, header.firstElementChild);
            }
        }

        const toolbar = document.createElement("form");
        toolbar.method = "post";
        toolbar.action = `/p/${slug}/handoff-selection/`;
        toolbar.className = "handoff-selection-toolbar";
        toolbar.innerHTML = `
            <input type="hidden" name="mode" value="selected">
            <span class="handoff-selection-count">0 selected</span>
            <select class="form-input" name="destination_engine" required>
                <option value="">Send selected to…</option>
                <option value="httpx">HTTPX</option>
                <option value="katana">Katana</option>
                <option value="nuclei">Nuclei</option>
            </select>
            <select class="form-input" name="auth_profile_id">${profileOptions()}</select>
            <select class="form-input" name="template_source" title="Nuclei template source">${templateSourceOptions()}</select>
            <button class="button scan-button" type="submit">Launch Handoff</button>
            <button class="button secondary handoff-clear" type="button">Clear</button>
        `;
        document.querySelector("main.content")?.appendChild(toolbar);
        bindTemplateSource(toolbar);

        toolbar.querySelector(".handoff-clear").addEventListener("click", () => {
            for (const cb of document.querySelectorAll(".handoff-row-checkbox")) cb.checked = false;
            for (const cb of document.querySelectorAll(".handoff-select-heading input")) cb.checked = false;
            updateToolbar();
        });

        toolbar.addEventListener("submit", (event) => {
            toolbar.querySelectorAll('input[name="source_ref"]').forEach(n => n.remove());
            const selected = Array.from(document.querySelectorAll(".handoff-row-checkbox:checked"));
            if (!selected.length) {
                event.preventDefault();
                return;
            }
            for (const cb of selected) {
                const input = document.createElement("input");
                input.type = "hidden";
                input.name = "source_ref";
                input.value = cb.value;
                toolbar.appendChild(input);
            }
        });

        function updateToolbar() {
            const count = document.querySelectorAll(".handoff-row-checkbox:checked").length;
            toolbar.querySelector(".handoff-selection-count").textContent = `${count} selected`;
            toolbar.classList.toggle("visible", count > 0);
        }
        updateToolbar();
    }

    if (window.location.pathname.endsWith("/findings/")) {
        const browser = document.getElementById("source-browser");
        if (browser) {
            const params = new URLSearchParams(window.location.search);
            const form = document.createElement("form");
            form.method = "post";
            form.action = `/p/${slug}/handoff-selection/`;
            form.className = "filtered-handoff-box";
            form.innerHTML = `
                <input type="hidden" name="mode" value="filtered">
                <span class="muted">Send the entire current Source Browser filter set, not only this page.</span>
                <select class="form-input" name="destination_engine" required>
                    <option value="">Send filtered to…</option>
                    <option value="httpx">HTTPX</option>
                    <option value="katana">Katana</option>
                    <option value="nuclei">Nuclei</option>
                </select>
                <select class="form-input" name="auth_profile_id">${profileOptions()}</select>
                <select class="form-input" name="template_source" title="Nuclei template source">${templateSourceOptions()}</select>
                <button class="button secondary" type="submit">Launch Filtered Handoff</button>
            `;
            const map = {
                engine: "filter_engine", status: "filter_status", severity: "filter_severity",
                context: "filter_context", host: "filter_host", q: "filter_q",
                template_id: "filter_template_id", interesting: "filter_interesting", pinned: "filter_pinned"
            };
            for (const [key, name] of Object.entries(map)) {
                const value = params.get(key);
                if (!value) continue;
                const input = document.createElement("input");
                input.type = "hidden"; input.name = name; input.value = value;
                form.appendChild(input);
            }
            browser.insertBefore(form, browser.querySelector(".table-wrap"));
            bindTemplateSource(form);
        }
    }
})();

(() => {

    "use strict";


    const profileElement =
        document.getElementById(
            "reconmancer-auth-profiles"
        );


    let profiles = [];


    if (profileElement) {

        try {

            profiles =
                JSON.parse(
                    profileElement.textContent
                    || "[]"
                );

        } catch (error) {

            console.error(
                "Could not parse auth profiles:",
                error
            );

            profiles = [];

        }

    }


    const projectMatch =
        window.location.pathname.match(
            /^\/p\/([^/]+)\//
        );


    if (!projectMatch) {
        return;
    }


    const projectSlug =
        projectMatch[
            1
        ];


    const runMatch =
        window.location.pathname.match(
            /^\/p\/[^/]+\/(httpx|katana|nuclei)\/run\/([^/]+)\//
        );


    function escapeHtml(
        value
    ) {

        return String(
            value
        )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );

    }


    function contextBadge(
        descriptor
    ) {

        const badge =
            document.createElement(
                "span"
            );


        if (
            descriptor.kind
            === "authenticated"
        ) {

            badge.className =
                (
                    "context-badge "
                    + "context-badge-authenticated"
                );


            const label =
                descriptor.profile_name
                || descriptor.profile_id
                || "AUTH";


            badge.innerHTML =
                (
                    "<span>AUTH</span>"
                    + "<span "
                    + 'class="context-profile-name">'
                    + escapeHtml(
                        label
                    )
                    + "</span>"
                );


            badge.title =
                descriptor.profile_id
                    ? (
                        "Authenticated with "
                        + descriptor.profile_id
                    )
                    : "Authenticated";

        } else {

            badge.className =
                (
                    "context-badge "
                    + "context-badge-anonymous"
                );


            badge.textContent =
                "ANON";


            badge.title =
                "Anonymous execution";

        }


        return badge;

    }


    function runIdFromHref(
        href
    ) {

        if (!href) {
            return null;
        }


        const match =
            href.match(
                /\/run\/([^/]+)\//
            );


        if (!match) {
            return null;
        }


        return decodeURIComponent(
            match[
                1
            ]
        );

    }


    function annotateRunElement(
        element,
        runId,
        contexts
    ) {

        if (
            !runId
            ||
            !contexts[
                runId
            ]
        ) {

            return;
        }


        if (
            element.dataset
                .contextBadged
            === "1"
        ) {

            return;
        }


        element.dataset
            .contextBadged =
            "1";


        element.insertAdjacentElement(
            "afterend",
            contextBadge(
                contexts[
                    runId
                ]
            )
        );

    }


    function annotateRunHistory(
        contexts
    ) {

        const links =
            document.querySelectorAll(
                'a[href*="/run/"]'
            );


        for (
            const link
            of links
        ) {

            const runId =
                runIdFromHref(
                    link.getAttribute(
                        "href"
                    )
                );


            annotateRunElement(
                link,
                runId,
                contexts
            );

        }


        const candidates =
            document.querySelectorAll(
                ".timeline-id, td.mono"
            );


        for (
            const element
            of candidates
        ) {

            if (
                element.querySelector(
                    "a"
                )
            ) {

                continue;
            }


            const value =
                (
                    element.textContent
                    || ""
                )
                .trim();


            if (
                contexts[
                    value
                ]
            ) {

                annotateRunElement(
                    element,
                    value,
                    contexts
                );

            }

        }

    }


    function addCurrentRunBadge(
        contexts
    ) {

        if (!runMatch) {
            return;
        }


        const runId =
            decodeURIComponent(
                runMatch[
                    2
                ]
            );


        const descriptor =
            contexts[
                runId
            ];


        if (!descriptor) {
            return;
        }


        const pageHeader =
            document.querySelector(
                ".page-header"
            );


        if (!pageHeader) {
            return;
        }


        if (
            pageHeader.querySelector(
                ".current-context"
            )
        ) {

            return;
        }


        const wrapper =
            document.createElement(
                "div"
            );


        wrapper.className =
            "current-context";


        wrapper.appendChild(
            contextBadge(
                descriptor
            )
        );


        pageHeader.appendChild(
            wrapper
        );

    }


    function profileOptions(
        inheritedId
    ) {

        let html =
            (
                '<option value="">'
                + "Select profile"
                + "</option>"
            );


        for (
            const profile
            of profiles
        ) {

            const selected =
                (
                    inheritedId
                    &&
                    profile.id
                    === inheritedId
                )
                    ? " selected"
                    : "";


            html +=
                (
                    '<option value="'
                    + escapeHtml(
                        profile.id
                    )
                    + '"'
                    + selected
                    + ">"
                    + escapeHtml(
                        profile.name
                    )
                    + " ("
                    + escapeHtml(
                        profile.id
                    )
                    + ")"
                    + "</option>"
                );

        }


        return html;

    }


    function severityControls() {

        return `
            <div class="auth-handoff-checks">

                <label>
                    <input
                        type="checkbox"
                        name="severity"
                        value="critical"
                        checked
                    >
                    Critical
                </label>

                <label>
                    <input
                        type="checkbox"
                        name="severity"
                        value="high"
                        checked
                    >
                    High
                </label>

                <label>
                    <input
                        type="checkbox"
                        name="severity"
                        value="medium"
                        checked
                    >
                    Medium
                </label>

                <label>
                    <input
                        type="checkbox"
                        name="severity"
                        value="low"
                        checked
                    >
                    Low
                </label>

                <label>
                    <input
                        type="checkbox"
                        name="severity"
                        value="info"
                        checked
                    >
                    Info
                </label>

            </div>
        `;

    }


    function katanaForm(
        sourceEngine,
        runId,
        inheritedId
    ) {

        return `
            <form
                method="post"
                class="auth-handoff-card"
                data-auth-handoff="1"
                action="/p/${escapeHtml(projectSlug)}/${escapeHtml(sourceEngine)}/run/${escapeHtml(runId)}/send-auth/katana/"
            >

                <h3>
                    Send Auth → Katana
                </h3>

                <p>
                    Standard, Headless or Deep crawler.
                    Browser credentials remain bound to
                    the selected profile's exact hosts.
                </p>

                <label class="form-label">
                    Authentication profile
                </label>

                <select
                    class="form-input handoff-profile"
                    name="auth_profile_id"
                    required
                >
                    ${profileOptions(inheritedId)}
                </select>

                <div
                    class="auth-handoff-eligibility"
                >
                    Select a profile to calculate
                    eligible source URLs.
                </div>

                <div class="auth-handoff-fields">
                    <div>
                        <label class="form-label">Crawler profile</label>
                        <select class="form-input" name="profile">
                            <option value="standard">Standard</option>
                            <option value="headless">Headless</option>
                            <option value="deep">Deep</option>
                        </select>
                    </div>

                    <div>
                        <label class="form-label">
                            Depth
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="depth"
                            value="3"
                            min="1"
                            max="10"
                        >
                    </div>

                    <div>
                        <label class="form-label">
                            Rate limit
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="rate_limit"
                            value="20"
                            min="1"
                            max="500"
                        >
                    </div>

                    <div>
                        <label class="form-label">
                            Concurrency
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="concurrency"
                            value="5"
                            min="1"
                            max="50"
                        >
                    </div>

                    <div>
                        <label class="form-label">
                            Parallelism
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="parallelism"
                            value="2"
                            min="1"
                            max="20"
                        >
                    </div>

                </div>

                <div class="auth-handoff-checks">

                    <label>
                        <input
                            type="checkbox"
                            name="js_crawl"
                            value="1"
                            checked
                        >
                        JavaScript crawl
                    </label>

                    <label>
                        <input
                            type="checkbox"
                            name="known_files"
                            value="1"
                            checked
                        >
                        Known files
                    </label>

                    <label>
                        <input
                            type="checkbox"
                            name="form_extraction"
                            value="1"
                            checked
                        >
                        Forms
                    </label>

                    <label>
                        <input
                            type="checkbox"
                            name="tech_detect"
                            value="1"
                            checked
                        >
                        Technologies
                    </label>

                </div>

                <div class="auth-handoff-safety">
                    Browser modes use an exact-host Chrome
                    authentication extension. no-scope stays
                    unavailable for authenticated crawling.
                </div>

                <button
                    class="button scan-button auth-handoff-submit"
                    type="submit"
                >
                    Launch Authenticated Katana
                </button>

            </form>
        `;

    }


    function httpxForm(
        sourceEngine,
        runId,
        inheritedId
    ) {

        return `
            <form
                method="post"
                class="auth-handoff-card"
                data-auth-handoff="1"
                action="/p/${escapeHtml(projectSlug)}/${escapeHtml(sourceEngine)}/run/${escapeHtml(runId)}/send-auth/httpx/"
            >

                <h3>
                    Send Auth → HTTPX
                </h3>

                <p>
                    Re-probe eligible discovered URLs
                    using the selected exact-host profile.
                </p>

                <label class="form-label">
                    Authentication profile
                </label>

                <select
                    class="form-input handoff-profile"
                    name="auth_profile_id"
                    required
                >
                    ${profileOptions(inheritedId)}
                </select>

                <div
                    class="auth-handoff-eligibility"
                >
                    Select a profile to calculate
                    eligible source URLs.
                </div>

                <div class="auth-handoff-fields">

                    <div>

                        <label class="form-label">
                            Rate limit
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="rate_limit"
                            value="10"
                            min="1"
                            max="1000"
                        >

                    </div>

                    <div>

                        <label class="form-label">
                            Redirect depth
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="redirect_depth"
                            value="10"
                            min="0"
                            max="50"
                        >

                    </div>

                </div>

                <div class="auth-handoff-checks">
                    <label>
                        <input type="checkbox" name="screenshots" value="1">
                        Authenticated screenshots
                    </label>
                </div>

                <div class="auth-handoff-safety">
                    Authenticated screenshots use exact-host
                    browser credential injection. Redirects may
                    continue without leaking credentials.
                </div>

                <button
                    class="button scan-button auth-handoff-submit"
                    type="submit"
                >
                    Launch Authenticated HTTPX
                </button>

            </form>
        `;

    }


    function nucleiForm(
        sourceEngine,
        runId,
        inheritedId
    ) {

        return `
            <form
                method="post"
                class="auth-handoff-card"
                data-auth-handoff="1"
                action="/p/${escapeHtml(projectSlug)}/${escapeHtml(sourceEngine)}/run/${escapeHtml(runId)}/send-auth/nuclei/"
            >

                <h3>
                    Send Auth → Nuclei
                </h3>

                <p>
                    Scan only source URLs that exactly
                    match the selected authentication
                    profile.
                </p>

                <label class="form-label">
                    Authentication profile
                </label>

                <select
                    class="form-input handoff-profile"
                    name="auth_profile_id"
                    required
                >
                    ${profileOptions(inheritedId)}
                </select>

                <div
                    class="auth-handoff-eligibility"
                >
                    Select a profile to calculate
                    eligible source URLs.
                </div>

                ${severityControls()}

                <div class="auth-handoff-fields">

                    <div>

                        <label class="form-label">
                            Template source
                        </label>

                        <select
                            class="form-input"
                            name="template_source"
                        >
                            <option value="default">
                                Default Nuclei
                            </option>
                            <option value="projectdiscovery">
                                nuclei-templates (ProjectDiscovery)
                            </option>
                        </select>

                    </div>

                    <div>

                        <label class="form-label">
                            Tags
                        </label>

                        <input
                            class="form-input"
                            type="text"
                            name="tags"
                            value=""
                            placeholder="Optional"
                        >

                    </div>

                    <div>

                        <label class="form-label">
                            Excluded tags
                        </label>

                        <input
                            class="form-input"
                            type="text"
                            name="exclude_tags"
                            value="dos,fuzz,bruteforce"
                        >

                    </div>

                    <div>

                        <label class="form-label">
                            Rate limit
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="rate_limit"
                            value="10"
                            min="1"
                            max="500"
                        >

                    </div>

                    <div>

                        <label class="form-label">
                            Concurrency
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="concurrency"
                            value="5"
                            min="1"
                            max="50"
                        >

                    </div>

                    <div>

                        <label class="form-label">
                            Bulk size
                        </label>

                        <input
                            class="form-input"
                            type="number"
                            name="bulk_size"
                            value="5"
                            min="1"
                            max="50"
                        >

                    </div>

                </div>

                <div class="auth-handoff-checks">
                    <label>
                        <input type="checkbox" name="allow_headless" value="1">
                        Allow authenticated headless templates
                    </label>
                </div>

                <div class="auth-handoff-safety">
                    Interactsh is forced off. Headless browser
                    credentials use exact-host injection.
                </div>

                <button
                    class="button scan-button auth-handoff-submit"
                    type="submit"
                >
                    Launch Authenticated Nuclei
                </button>

            </form>
        `;

    }


    async function refreshEligibility(
        form,
        sourceEngine,
        runId
    ) {

        const select =
            form.querySelector(
                ".handoff-profile"
            );


        const output =
            form.querySelector(
                ".auth-handoff-eligibility"
            );


        const submit =
            form.querySelector(
                ".auth-handoff-submit"
            );


        if (
            !select
            ||
            !output
            ||
            !submit
        ) {

            return;
        }


        const profileId =
            select.value;


        output.className =
            "auth-handoff-eligibility";


        if (!profileId) {

            output.textContent =
                (
                    "Select a profile to calculate "
                    + "eligible source URLs."
                );


            submit.disabled =
                true;


            return;

        }


        output.textContent =
            "Calculating exact-host eligibility…";


        submit.disabled =
            true;


        try {

            const url =
                (
                    `/p/${projectSlug}/auth-handoffs/`
                    + `${sourceEngine}/${runId}/`
                    + "eligibility.json"
                    + "?profile_id="
                    + encodeURIComponent(
                        profileId
                    )
                );


            const response =
                await fetch(
                    url,
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    (
                        "Eligibility request failed "
                        + response.status
                    )
                );

            }


            const data =
                await response.json();


            output.textContent =
                (
                    `${data.eligible} of `
                    + `${data.total} source URLs `
                    + "exactly match this profile. "
                    + `${data.excluded} excluded.`
                );


            if (
                data.eligible <= 0
            ) {

                output.classList.add(
                    "bad"
                );


                submit.disabled =
                    true;

            } else if (
                data.excluded > 0
            ) {

                output.classList.add(
                    "warning"
                );


                submit.disabled =
                    false;

            } else {

                output.classList.add(
                    "good"
                );


                submit.disabled =
                    false;

            }

        } catch (error) {

            console.error(
                "Auth handoff eligibility failed:",
                error
            );


            output.textContent =
                (
                    "Could not calculate eligibility."
                );


            output.classList.add(
                "bad"
            );


            submit.disabled =
                true;

        }

    }


    function wireHandoffForms(
        panel,
        sourceEngine,
        runId
    ) {

        const forms =
            panel.querySelectorAll(
                '[data-auth-handoff="1"]'
            );


        for (
            const form
            of forms
        ) {

            const select =
                form.querySelector(
                    ".handoff-profile"
                );


            if (select) {

                select.addEventListener(
                    "change",
                    () => {

                        refreshEligibility(
                            form,
                            sourceEngine,
                            runId
                        );

                    }
                );

            }


            form.addEventListener(
                "submit",
                event => {

                    if (
                        !select
                        ||
                        !select.value
                    ) {

                        event.preventDefault();


                        window.alert(
                            (
                                "Select an authentication "
                                + "profile."
                            )
                        );

                    }

                }
            );


            refreshEligibility(
                form,
                sourceEngine,
                runId
            );

        }

    }


    function addAuthenticatedHandoffs(
        contexts
    ) {

        if (!runMatch) {
            return;
        }


        const sourceEngine =
            runMatch[
                1
            ];


        if (
            sourceEngine
            !== "httpx"
            &&
            sourceEngine
            !== "katana"
        ) {

            return;
        }


        if (
            document.querySelector(
                ".auth-handoff-panel"
            )
        ) {

            return;
        }


        const runId =
            decodeURIComponent(
                runMatch[
                    2
                ]
            );


        const descriptor =
            contexts[
                runId
            ] || {};


        const inheritedId =
            (
                descriptor.kind
                === "authenticated"
            )
                ? descriptor.profile_id
                : null;


        const panel =
            document.createElement(
                "section"
            );


        panel.className =
            "panel auth-handoff-panel";


        let cards = "";


        if (profiles.length) {

            if (
                sourceEngine
                === "httpx"
            ) {

                cards += katanaForm(
                    sourceEngine,
                    runId,
                    inheritedId
                );


                cards += nucleiForm(
                    sourceEngine,
                    runId,
                    inheritedId
                );

            } else {

                cards += httpxForm(
                    sourceEngine,
                    runId,
                    inheritedId
                );


                cards += nucleiForm(
                    sourceEngine,
                    runId,
                    inheritedId
                );

            }

        }


        panel.innerHTML =
            `
                <div class="panel-header">

                    <div>

                        <h2>
                            Authenticated Handoffs
                        </h2>

                        <p class="muted">
                            Launch a destination engine
                            with credentials applied only
                            to exact matching hosts.
                        </p>

                    </div>

                </div>

                <div class="auth-handoff-intro">

                    Source run:
                    <strong>${escapeHtml(runId)}</strong>.

                    ${
                        inheritedId
                            ? (
                                "Its authentication profile "
                                + "is preselected below."
                            )
                            : (
                                "The source is anonymous; "
                                + "choose a profile explicitly."
                            )
                    }

                    URLs outside the selected profile
                    remain preserved in this source run
                    and are excluded only from the
                    authenticated destination handoff.

                </div>

                ${
                    profiles.length
                        ? (
                            '<div class="auth-handoff-grid">'
                            + cards
                            + "</div>"
                        )
                        : (
                            '<div class="auth-handoff-eligibility bad">'
                            + "No authentication profiles configured. "
                            + "Create one in Settings first."
                            + "</div>"
                        )
                }
            `;


        const main =
            document.querySelector(
                "main.content"
            );


        if (!main) {
            return;
        }


        main.appendChild(
            panel
        );


        if (profiles.length) {

            wireHandoffForms(
                panel,
                sourceEngine,
                runId
            );

        }

    }


    async function initialize() {

        try {

            const response =
                await fetch(
                    (
                        `/p/${projectSlug}/`
                        + "run-contexts.json"
                    ),
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    (
                        "Context request failed "
                        + response.status
                    )
                );

            }


            const data =
                await response.json();


            const contexts =
                data.runs
                || {};


            annotateRunHistory(
                contexts
            );


            addCurrentRunBadge(
                contexts
            );


            addAuthenticatedHandoffs(
                contexts
            );

        } catch (error) {

            console.error(
                (
                    "Reconmancer context/handoff "
                    + "initialization failed:"
                ),
                error
            );

        }

    }


    initialize();

})();

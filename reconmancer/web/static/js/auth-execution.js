(() => {

    "use strict";


    const dataElement =
        document.getElementById(
            "reconmancer-auth-profiles"
        );


    if (!dataElement) {
        return;
    }


    let profiles = [];


    try {

        profiles =
            JSON.parse(
                dataElement.textContent
                || "[]"
            );

    } catch (error) {

        console.error(
            "Could not load authentication profiles:",
            error
        );

        profiles = [];

    }


    const configurations = [
        {
            anonymousSuffix:
                "/httpx/new/",

            authenticatedSuffix:
                "/httpx/auth/new/",

            note:
                "Authenticated HTTPX keeps redirect discovery, "
                + "but credentials are only eligible on exact "
                + "profile hosts. Authenticated screenshots use "
                + "exact-host browser credential injection.",

            disableWhenAuthenticated: [],

            forceStandardKatana:
                false,

            forceNoInteractsh:
                false,
        },

        {
            anonymousSuffix:
                "/katana/new/",

            authenticatedSuffix:
                "/katana/auth/new/",

            note:
                "Authenticated Katana remains exact-FQDN scoped. "
                + "Standard, Headless and Deep can use exact-host "
                + "browser credential injection; Disable Scope remains unavailable.",

            disableWhenAuthenticated: [
                "no_scope"
            ],

            forceStandardKatana:
                false,

            forceNoInteractsh:
                false,
        },

        {
            anonymousSuffix:
                "/nuclei/new/",

            authenticatedSuffix:
                "/nuclei/auth/new/",

            note:
                "Authenticated Nuclei uses domain-scoped secret "
                + "files and exact-host browser credential injection. "
                + "Interactsh is forced off for authenticated runs.",

            disableWhenAuthenticated: [],

            forceStandardKatana:
                false,

            forceNoInteractsh:
                true,
        },
    ];


    function matchingConfiguration(
        form
    ) {

        const action =
            form.getAttribute(
                "action"
            )
            || "";


        for (
            const config
            of configurations
        ) {

            if (
                action.endsWith(
                    config.anonymousSuffix
                )
            ) {

                return config;

            }

        }


        return null;

    }


    function selectedProfile(
        select
    ) {

        if (!select.value) {
            return null;
        }


        return (
            profiles.find(
                profile =>
                    profile.id
                    === select.value
            )
            || null
        );

    }


    function renderHosts(
        container,
        profile
    ) {

        container.innerHTML =
            "";


        if (!profile) {
            return;
        }


        for (
            const host
            of (
                profile.hosts
                || []
            )
        ) {

            const chip =
                document.createElement(
                    "span"
                );


            chip.className =
                "auth-host-chip";


            chip.textContent =
                host;


            container.appendChild(
                chip
            );

        }

    }


    function setNamedInputsDisabled(
        form,
        names,
        disabled
    ) {

        for (
            const name
            of names
        ) {

            const inputs =
                form.querySelectorAll(
                    `[name="${name}"]`
                );


            for (
                const input
                of inputs
            ) {

                if (disabled) {

                    input.checked =
                        false;

                }


                input.disabled =
                    disabled;

            }

        }

    }


    function setKatanaProfileMode(
        form,
        authenticated
    ) {

        const radios =
            form.querySelectorAll(
                'input[name="profile"]'
            );


        if (!radios.length) {
            return;
        }


        for (
            const radio
            of radios
        ) {

            if (authenticated) {

                if (
                    radio.value
                    === "standard"
                ) {

                    radio.checked =
                        true;

                    radio.disabled =
                        false;

                } else {

                    radio.checked =
                        false;

                    radio.disabled =
                        true;

                }

            } else {

                radio.disabled =
                    false;

            }

        }

    }


    function forceNoInteractsh(
        form,
        authenticated
    ) {

        const input =
            form.querySelector(
                '[name="no_interactsh"]'
            );


        if (!input) {
            return;
        }


        if (authenticated) {

            input.checked =
                true;

            input.disabled =
                true;

        } else {

            input.disabled =
                false;

        }

    }


    function buildExecutionBox(
        form,
        config
    ) {

        const originalAction =
            form.getAttribute(
                "action"
            );


        const box =
            document.createElement(
                "div"
            );


        box.className =
            "auth-execution-box";


        const title =
            document.createElement(
                "div"
            );


        title.className =
            "auth-execution-title";


        title.textContent =
            "Execution Context";


        box.appendChild(
            title
        );


        const modeRow =
            document.createElement(
                "div"
            );


        modeRow.className =
            "auth-mode-row";


        const anonymousLabel =
            document.createElement(
                "label"
            );


        anonymousLabel.innerHTML =
            `
            <input
                type="radio"
                name="execution_context"
                value="anonymous"
                checked
            >
            Anonymous
            `;


        const authenticatedLabel =
            document.createElement(
                "label"
            );


        authenticatedLabel.innerHTML =
            `
            <input
                type="radio"
                name="execution_context"
                value="authenticated"
            >
            Authenticated
            `;


        modeRow.appendChild(
            anonymousLabel
        );


        modeRow.appendChild(
            authenticatedLabel
        );


        box.appendChild(
            modeRow
        );


        const profileArea =
            document.createElement(
                "div"
            );


        profileArea.className =
            "auth-profile-area";


        const label =
            document.createElement(
                "label"
            );


        label.className =
            "form-label";


        label.textContent =
            "Authentication Profile";


        profileArea.appendChild(
            label
        );


        const select =
            document.createElement(
                "select"
            );


        select.className =
            "form-input";


        select.name =
            "auth_profile_id";


        select.disabled =
            true;


        const emptyOption =
            document.createElement(
                "option"
            );


        emptyOption.value =
            "";


        emptyOption.textContent =
            profiles.length
                ? "Select profile"
                : "No profiles configured";


        select.appendChild(
            emptyOption
        );


        for (
            const profile
            of profiles
        ) {

            const option =
                document.createElement(
                    "option"
                );


            option.value =
                profile.id;


            option.textContent =
                `${profile.name} (${profile.id})`;


            select.appendChild(
                option
            );

        }


        profileArea.appendChild(
            select
        );


        const hosts =
            document.createElement(
                "div"
            );


        hosts.className =
            "auth-host-list";


        profileArea.appendChild(
            hosts
        );


        if (!profiles.length) {

            const empty =
                document.createElement(
                    "div"
                );


            empty.className =
                "auth-profile-empty";


            empty.textContent =
                "Create an authentication profile in Settings first.";


            profileArea.appendChild(
                empty
            );

        }


        box.appendChild(
            profileArea
        );


        const note =
            document.createElement(
                "div"
            );


        note.className =
            "auth-execution-note";


        note.textContent =
            "Anonymous is the default. "
            + config.note;


        box.appendChild(
            note
        );


        const firstChild =
            form.firstElementChild;


        if (firstChild) {

            form.insertBefore(
                box,
                firstChild
            );

        } else {

            form.appendChild(
                box
            );

        }


        const anonymousRadio =
            anonymousLabel.querySelector(
                "input"
            );


        const authenticatedRadio =
            authenticatedLabel.querySelector(
                "input"
            );


        if (!profiles.length) {

            authenticatedRadio.disabled =
                true;

        }


        function applyMode() {

            const authenticated =
                authenticatedRadio.checked;


            if (authenticated) {

                form.setAttribute(
                    "action",
                    originalAction.replace(
                        config.anonymousSuffix,
                        config.authenticatedSuffix
                    )
                );


                select.disabled =
                    false;


                setNamedInputsDisabled(
                    form,
                    config.disableWhenAuthenticated,
                    true
                );


                if (
                    config.forceStandardKatana
                ) {

                    setKatanaProfileMode(
                        form,
                        true
                    );

                }


                if (
                    config.forceNoInteractsh
                ) {

                    forceNoInteractsh(
                        form,
                        true
                    );

                }


                note.classList.add(
                    "warning"
                );

            } else {

                form.setAttribute(
                    "action",
                    originalAction
                );


                select.disabled =
                    true;


                setNamedInputsDisabled(
                    form,
                    config.disableWhenAuthenticated,
                    false
                );


                if (
                    config.forceStandardKatana
                ) {

                    setKatanaProfileMode(
                        form,
                        false
                    );

                }


                if (
                    config.forceNoInteractsh
                ) {

                    forceNoInteractsh(
                        form,
                        false
                    );

                }


                note.classList.remove(
                    "warning"
                );

            }

        }


        anonymousRadio.addEventListener(
            "change",
            applyMode
        );


        authenticatedRadio.addEventListener(
            "change",
            applyMode
        );


        select.addEventListener(
            "change",
            () => {

                renderHosts(
                    hosts,
                    selectedProfile(
                        select
                    )
                );

            }
        );


        form.addEventListener(
            "submit",
            event => {

                if (
                    authenticatedRadio.checked
                    &&
                    !select.value
                ) {

                    event.preventDefault();


                    window.alert(
                        "Select an authentication profile."
                    );

                }

            }
        );


        applyMode();

    }


    const forms =
        document.querySelectorAll(
            "form[action]"
        );


    for (
        const form
        of forms
    ) {

        const config =
            matchingConfiguration(
                form
            );


        if (!config) {
            continue;
        }


        buildExecutionBox(
            form,
            config
        );

    }

})();

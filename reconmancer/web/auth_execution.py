from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    redirect,
    request,
    url_for,
)

from reconmancer.core.auth_profiles import (
    filter_targets_for_profile,
    get_profile,
    list_profiles,
)

from reconmancer.core.auth_runtime import (
    profile_has_credentials,
)

from reconmancer.core.authenticated_jobs import (
    launch_httpx_authenticated_job,
    launch_katana_authenticated_job,
    launch_nuclei_authenticated_job,
)

from reconmancer.core.projects import (
    load_project,
)


HOME = Path("/opt/reconmancer")


auth_execution_blueprint = Blueprint(
    "auth_execution",
    __name__,
)


def project_or_404(
    slug: str,
):

    try:
        return load_project(
            HOME,
            slug,
        )

    except (
        ValueError,
        FileNotFoundError,
    ):
        abort(404)


def collect_targets() -> tuple[
    list[str],
    str | None,
]:

    sources = []

    uploaded = request.files.get("targets_file")

    filename = None

    if uploaded and uploaded.filename:
        filename = uploaded.filename.strip()

        if not filename.lower().endswith(".txt"):
            abort(
                400,
                ("Target upload must be a .txt file."),
            )

        raw = uploaded.read()

        if len(raw) > (10 * 1024 * 1024):
            abort(
                400,
                ("Target file is larger than 10 MB."),
            )

        try:
            text = raw.decode("utf-8")

        except UnicodeDecodeError:
            text = raw.decode(
                "utf-8",
                errors="ignore",
            )

        sources.append(text)

    pasted = request.form.get(
        "targets",
        "",
    )

    if pasted.strip():
        sources.append(pasted)

    if not sources:
        abort(
            400,
            ("Upload a targets.txt file or enter targets."),
        )

    targets = []

    seen = set()

    for source in sources:
        for line in source.splitlines():
            value = line.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            if value in seen:
                continue

            seen.add(value)

            targets.append(value)

    if not targets:
        abort(
            400,
            "No valid targets found.",
        )

    if len(targets) > 100000:
        abort(
            400,
            ("Maximum 100,000 targets per job."),
        )

    return (
        targets,
        filename,
    )


def integer_option(
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:

    try:
        value = int(
            request.form.get(
                name,
                str(default),
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        value = default

    return max(
        minimum,
        min(
            value,
            maximum,
        ),
    )


def selected_auth_profile(
    project: dict,
    targets: list[str],
) -> tuple[
    str,
    dict,
]:

    profile_id = request.form.get(
        "auth_profile_id",
        "",
    ).strip()

    if not profile_id:
        abort(
            400,
            ("Select an authentication profile."),
        )

    try:
        profile = get_profile(
            project["root"],
            profile_id,
        )

    except ValueError:
        abort(
            400,
            ("Invalid authentication profile ID."),
        )

    if profile is None:
        abort(
            400,
            ("Authentication profile does not exist."),
        )

    if not profile_has_credentials(profile):
        abort(
            400,
            ("The selected profile contains no cookie or custom headers."),
        )

    (
        allowed,
        rejected,
    ) = filter_targets_for_profile(
        profile,
        targets,
    )

    if rejected:
        example = ", ".join(rejected[:5])

        abort(
            400,
            (
                "Authenticated scan rejected. "
                "Every starting target must exactly "
                "match the selected profile. "
                "Rejected: " + example
            ),
        )

    if len(allowed) != len(targets):
        abort(
            400,
            ("Authentication target validation failed."),
        )

    return (
        profile_id,
        profile,
    )


@auth_execution_blueprint.app_context_processor
def inject_auth_profiles():

    view_args = request.view_args or {}

    slug = view_args.get("slug")

    if not slug:
        return {"scan_auth_profiles": []}

    try:
        project = load_project(
            HOME,
            slug,
        )

    except (
        ValueError,
        FileNotFoundError,
    ):
        return {"scan_auth_profiles": []}

    profiles = list_profiles(project["root"])

    public = []

    for profile in profiles:
        public.append(
            {
                "id": profile.get("id"),
                "name": profile.get("name"),
                "hosts": profile.get(
                    "hosts",
                    [],
                ),
                "host_count": profile.get(
                    "host_count",
                    0,
                ),
                "header_names": (
                    profile.get(
                        "header_names",
                        [],
                    )
                ),
                "has_cookie": bool(
                    profile.get(
                        "has_cookie",
                        False,
                    )
                ),
            }
        )

    return {"scan_auth_profiles": public}


@auth_execution_blueprint.route(
    "/p/<slug>/httpx/auth/new/",
    methods=[
        "POST",
    ],
)
def httpx_authenticated_scan(
    slug: str,
):

    project = project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_targets()

    (
        profile_id,
        profile,
    ) = selected_auth_profile(
        project,
        targets,
    )

    payload = {
        "target_count": len(targets),
        "rate_limit": (
            integer_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=1000,
            )
        ),
        "redirect_depth": (
            integer_option(
                "redirect_depth",
                default=10,
                minimum=0,
                maximum=50,
            )
        ),
        "screenshots": (request.form.get("screenshots") == "1"),
        "context": (f"auth:{profile_id}"),
        "auth_profile_id": (profile_id),
        "uploaded_file": (filename),
    }

    launch_httpx_authenticated_job(
        project,
        payload,
        targets,
    )

    return redirect(
        url_for(
            "httpx_index",
            slug=slug,
        )
    )


@auth_execution_blueprint.route(
    "/p/<slug>/katana/auth/new/",
    methods=[
        "POST",
    ],
)
def katana_authenticated_scan(
    slug: str,
):

    project = project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_targets()

    (
        profile_id,
        profile,
    ) = selected_auth_profile(
        project,
        targets,
    )

    crawler_profile = request.form.get(
        "profile",
        "standard",
    )

    if crawler_profile not in {
        "standard",
        "headless",
        "deep",
    }:
        crawler_profile = "standard"

    if request.form.get("no_scope") == "1":
        abort(
            400,
            ("Authenticated Katana cannot disable crawl scope."),
        )

    strategy = request.form.get(
        "page_load_strategy",
        "heuristic",
    )

    if strategy not in {
        "heuristic",
        "load",
        "domcontentloaded",
        "networkidle",
        "none",
    }:
        strategy = "heuristic"

    payload = {
        "target_count": len(targets),
        "profile": crawler_profile,
        "depth": (
            integer_option(
                "depth",
                default=3,
                minimum=1,
                maximum=10,
            )
        ),
        "rate_limit": (
            integer_option(
                "rate_limit",
                default=20,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "parallelism": (
            integer_option(
                "parallelism",
                default=2,
                minimum=1,
                maximum=20,
            )
        ),
        "page_load_strategy": (strategy),
        "js_crawl": (request.form.get("js_crawl") == "1"),
        "known_files": (request.form.get("known_files") == "1"),
        "form_extraction": (request.form.get("form_extraction") == "1"),
        "tech_detect": (request.form.get("tech_detect") == "1"),
        "no_scope": False,
        "context": (f"auth:{profile_id}"),
        "auth_profile_id": (profile_id),
        "uploaded_file": (filename),
    }

    launch_katana_authenticated_job(
        project,
        payload,
        targets,
    )

    return redirect(
        url_for(
            "katana_index",
            slug=slug,
        )
    )


@auth_execution_blueprint.route(
    "/p/<slug>/nuclei/auth/new/",
    methods=[
        "POST",
    ],
)
def nuclei_authenticated_scan(
    slug: str,
):

    project = project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_targets()

    (
        profile_id,
        profile,
    ) = selected_auth_profile(
        project,
        targets,
    )

    severities = request.form.getlist("severity")

    if not severities:
        severities = [
            "info",
            "low",
            "medium",
            "high",
            "critical",
        ]

    payload = {
        "target_count": len(targets),
        "severities": (severities),
        "tags": (
            request.form.get(
                "tags",
                "",
            ).strip()
        ),
        "exclude_tags": (
            request.form.get(
                "exclude_tags",
                "dos,fuzz,bruteforce",
            ).strip()
        ),
        "rate_limit": (
            integer_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "bulk_size": (
            integer_option(
                "bulk_size",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "no_interactsh": True,
        "allow_headless": (request.form.get("allow_headless") == "1"),
        "context": (f"auth:{profile_id}"),
        "auth_profile_id": (profile_id),
        "uploaded_file": (filename),
    }

    launch_nuclei_authenticated_job(
        project,
        payload,
        targets,
    )

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )

from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    request,
    url_for,
)

from reconmancer.core.auth_profiles import (
    get_profile,
    list_profiles,
    profile_applies_to_target,
)

from reconmancer.core.auth_runtime import (
    profile_has_credentials,
)

from reconmancer.core.authenticated_jobs import (
    launch_httpx_authenticated_job,
    launch_katana_authenticated_job,
    launch_nuclei_authenticated_job,
)

from reconmancer.core.database import (
    connect,
)

from reconmancer.core.handoffs import (
    attach_destination_job,
    collect_httpx_targets,
    collect_katana_targets,
    create_handoff,
    mark_handoff_failed,
)

from reconmancer.core.projects import (
    load_project,
)


HOME = Path("/opt/reconmancer")


auth_handoffs_blueprint = Blueprint(
    "auth_handoffs",
    __name__,
)


VALID_SOURCE_ENGINES = {
    "httpx",
    "katana",
}


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


def template_source_option() -> str:
    value = request.form.get("template_source", "default").strip().lower()
    if value not in {"default", "projectdiscovery"}:
        return "default"
    return value


def get_source_run(
    db_path: Path,
    engine: str,
    run_id: str,
) -> dict | None:

    connection = connect(db_path)

    try:
        row = connection.execute(
            """
            SELECT
                id,
                engine,
                profile,
                context,
                status,
                started_at,
                finished_at,
                input_count,
                result_count

            FROM runs

            WHERE
                id = ?
                AND engine = ?
            """,
            (
                run_id,
                engine,
            ),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def source_targets(
    db_path: Path,
    engine: str,
    run_id: str,
):

    if engine == "httpx":
        return collect_httpx_targets(
            db_path,
            run_id,
        )

    if engine == "katana":
        return collect_katana_targets(
            db_path,
            run_id,
        )

    raise ValueError((f"Unsupported handoff source engine: {engine}"))


def target_value(
    item,
) -> str | None:

    if isinstance(
        item,
        str,
    ):
        value = item.strip()

        return value or None

    if isinstance(
        item,
        dict,
    ):
        for key in (
            "target",
            "normalized_url",
            "url",
        ):
            value = item.get(key)

            if not isinstance(
                value,
                str,
            ):
                continue

            value = value.strip()

            if value:
                return value

    return None


def filter_source_targets(
    profile: dict,
    items,
) -> tuple[
    list,
    int,
]:

    allowed = []

    excluded = 0

    for item in items:
        value = target_value(item)

        if not value:
            excluded += 1
            continue

        if profile_applies_to_target(
            profile,
            value,
        ):
            allowed.append(item)

        else:
            excluded += 1

    return (
        allowed,
        excluded,
    )


def inherited_profile_id(
    source_run: dict,
) -> str | None:

    context = str(source_run.get("context") or "")

    if not context.startswith("auth:"):
        return None

    value = context[len("auth:") :].strip()

    return value or None


def resolve_profile(
    project: dict,
    source_run: dict,
) -> tuple[
    str,
    dict,
]:

    profile_id = request.form.get(
        "auth_profile_id",
        "",
    ).strip()

    if not profile_id:
        inherited = inherited_profile_id(source_run)

        if inherited:
            profile_id = inherited

    if not profile_id:
        abort(
            400,
            ("Select an authentication profile for this handoff."),
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
            ("Selected authentication profile contains no credentials."),
        )

    return (
        profile_id,
        profile,
    )


def prepare_authenticated_targets(
    project: dict,
    engine: str,
    run_id: str,
) -> tuple[
    dict,
    str,
    dict,
    list,
    int,
    int,
]:

    source_run = get_source_run(
        project["database"],
        engine,
        run_id,
    )

    if source_run is None:
        abort(404)

    (
        profile_id,
        profile,
    ) = resolve_profile(
        project,
        source_run,
    )

    items = source_targets(
        project["database"],
        engine,
        run_id,
    )

    if not items:
        abort(
            400,
            ("Source run has no URLs available for handoff."),
        )

    (
        allowed,
        excluded,
    ) = filter_source_targets(
        profile,
        items,
    )

    if not allowed:
        abort(
            400,
            ("No source URLs exactly match the selected authentication profile."),
        )

    return (
        source_run,
        profile_id,
        profile,
        allowed,
        excluded,
        len(items),
    )


def create_authenticated_handoff(
    *,
    project: dict,
    source_engine: str,
    source_run_id: str,
    destination_engine: str,
    destination_profile: str,
    profile_id: str,
    allowed_targets: list,
    excluded_count: int,
    source_count: int,
    options: dict,
) -> dict:

    complete_options = {
        **options,
        "execution_context": ("authenticated"),
        "auth_profile_id": (profile_id),
        "source_target_count": (source_count),
        "excluded_target_count": (excluded_count),
    }

    return create_handoff(
        db_path=project["database"],
        project_root=project["root"],
        source_engine=(source_engine),
        source_run_id=(source_run_id),
        destination_engine=(destination_engine),
        destination_profile=(destination_profile),
        targets=allowed_targets,
        options=(complete_options),
    )


def handoff_payload(
    *,
    options: dict,
    handoff: dict,
    source_engine: str,
    source_run_id: str,
    profile_id: str,
) -> dict:

    return {
        **options,
        "target_count": (handoff["target_count"]),
        "source_handoff_id": (handoff["id"]),
        "source_engine": (source_engine),
        "source_run_id": (source_run_id),
        "context": (f"auth:{profile_id}"),
        "auth_profile_id": (profile_id),
    }


def launch_and_attach(
    *,
    project: dict,
    handoff: dict,
    launcher,
    payload: dict,
) -> str:

    db = project["database"]

    try:
        job_id = launcher(
            project,
            payload,
            target_file=(handoff["target_file"]),
        )

        attach_destination_job(
            db,
            handoff["id"],
            job_id,
        )

        return job_id

    except Exception as exc:
        mark_handoff_failed(
            db,
            handoff["id"],
            str(exc),
        )

        raise


def context_descriptor(
    context: str | None,
    profile_names: dict[
        str,
        str,
    ],
) -> dict:

    value = str(context or "anonymous")

    if value.startswith("auth:"):
        profile_id = value[len("auth:") :].strip()

        profile_name = profile_names.get(profile_id)

        return {
            "kind": ("authenticated"),
            "raw": value,
            "profile_id": (profile_id),
            "profile_name": (profile_name),
            "label": (profile_name or profile_id or "Authenticated"),
        }

    return {
        "kind": "anonymous",
        "raw": value,
        "profile_id": None,
        "profile_name": None,
        "label": "Anonymous",
    }


@auth_handoffs_blueprint.route("/p/<slug>/run-contexts.json")
def run_contexts(
    slug: str,
):

    project = project_or_404(slug)

    profiles = list_profiles(project["root"])

    profile_names = {
        str(profile.get("id")): str(profile.get("name") or profile.get("id"))
        for profile in profiles
        if profile.get("id")
    }

    connection = connect(project["database"])

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                engine,
                context

            FROM runs

            ORDER BY
                started_at DESC

            LIMIT 5000
            """
        ).fetchall()

    finally:
        connection.close()

    output = {}

    for row in rows:
        item = dict(row)

        descriptor = context_descriptor(
            item.get("context"),
            profile_names,
        )

        descriptor["engine"] = item.get("engine")

        output[item["id"]] = descriptor

    return jsonify({"runs": output})


@auth_handoffs_blueprint.route(
    ("/p/<slug>/auth-handoffs/<source_engine>/<run_id>/eligibility.json")
)
def auth_handoff_eligibility(
    slug: str,
    source_engine: str,
    run_id: str,
):

    if source_engine not in VALID_SOURCE_ENGINES:
        abort(404)

    project = project_or_404(slug)

    source_run = get_source_run(
        project["database"],
        source_engine,
        run_id,
    )

    if source_run is None:
        abort(404)

    profile_id = request.args.get(
        "profile_id",
        "",
    ).strip()

    if not profile_id:
        return jsonify(
            {
                "total": 0,
                "eligible": 0,
                "excluded": 0,
            }
        )

    try:
        profile = get_profile(
            project["root"],
            profile_id,
        )

    except ValueError:
        abort(400)

    if profile is None:
        abort(404)

    items = source_targets(
        project["database"],
        source_engine,
        run_id,
    )

    (
        allowed,
        excluded,
    ) = filter_source_targets(
        profile,
        items,
    )

    return jsonify(
        {
            "total": len(items),
            "eligible": len(allowed),
            "excluded": (excluded),
            "profile_id": (profile_id),
        }
    )


@auth_handoffs_blueprint.route(
    ("/p/<slug>/httpx/run/<run_id>/send-auth/katana/"),
    methods=[
        "POST",
    ],
)
def httpx_send_auth_katana(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    (
        source_run,
        profile_id,
        profile,
        allowed,
        excluded,
        source_count,
    ) = prepare_authenticated_targets(
        project,
        "httpx",
        run_id,
    )

    crawler_profile = request.form.get("profile", "standard")
    if crawler_profile not in {"standard", "headless", "deep"}:
        crawler_profile = "standard"

    options = {
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
        "page_load_strategy": ("heuristic"),
        "js_crawl": (request.form.get("js_crawl") == "1"),
        "known_files": (request.form.get("known_files") == "1"),
        "form_extraction": (request.form.get("form_extraction") == "1"),
        "tech_detect": (request.form.get("tech_detect") == "1"),
        "no_scope": False,
    }

    handoff = create_authenticated_handoff(
        project=project,
        source_engine="httpx",
        source_run_id=run_id,
        destination_engine="katana",
        destination_profile=crawler_profile,
        profile_id=profile_id,
        allowed_targets=allowed,
        excluded_count=excluded,
        source_count=source_count,
        options=options,
    )

    payload = handoff_payload(
        options=options,
        handoff=handoff,
        source_engine="httpx",
        source_run_id=run_id,
        profile_id=profile_id,
    )

    launch_and_attach(
        project=project,
        handoff=handoff,
        launcher=(launch_katana_authenticated_job),
        payload=payload,
    )

    return redirect(
        url_for(
            "katana_index",
            slug=slug,
        )
    )


@auth_handoffs_blueprint.route(
    ("/p/<slug>/httpx/run/<run_id>/send-auth/nuclei/"),
    methods=[
        "POST",
    ],
)
def httpx_send_auth_nuclei(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    (
        source_run,
        profile_id,
        profile,
        allowed,
        excluded,
        source_count,
    ) = prepare_authenticated_targets(
        project,
        "httpx",
        run_id,
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

    options = {
        "template_source": template_source_option(),
        "severities": severities,
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
    }

    handoff = create_authenticated_handoff(
        project=project,
        source_engine="httpx",
        source_run_id=run_id,
        destination_engine="nuclei",
        destination_profile="web-safe",
        profile_id=profile_id,
        allowed_targets=allowed,
        excluded_count=excluded,
        source_count=source_count,
        options=options,
    )

    payload = handoff_payload(
        options=options,
        handoff=handoff,
        source_engine="httpx",
        source_run_id=run_id,
        profile_id=profile_id,
    )

    launch_and_attach(
        project=project,
        handoff=handoff,
        launcher=(launch_nuclei_authenticated_job),
        payload=payload,
    )

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )


@auth_handoffs_blueprint.route(
    ("/p/<slug>/katana/run/<run_id>/send-auth/httpx/"),
    methods=[
        "POST",
    ],
)
def katana_send_auth_httpx(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    (
        source_run,
        profile_id,
        profile,
        allowed,
        excluded,
        source_count,
    ) = prepare_authenticated_targets(
        project,
        "katana",
        run_id,
    )

    options = {
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
    }

    handoff = create_authenticated_handoff(
        project=project,
        source_engine="katana",
        source_run_id=run_id,
        destination_engine="httpx",
        destination_profile="full",
        profile_id=profile_id,
        allowed_targets=allowed,
        excluded_count=excluded,
        source_count=source_count,
        options=options,
    )

    payload = handoff_payload(
        options=options,
        handoff=handoff,
        source_engine="katana",
        source_run_id=run_id,
        profile_id=profile_id,
    )

    launch_and_attach(
        project=project,
        handoff=handoff,
        launcher=(launch_httpx_authenticated_job),
        payload=payload,
    )

    return redirect(
        url_for(
            "httpx_index",
            slug=slug,
        )
    )


@auth_handoffs_blueprint.route(
    ("/p/<slug>/katana/run/<run_id>/send-auth/nuclei/"),
    methods=[
        "POST",
    ],
)
def katana_send_auth_nuclei(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    (
        source_run,
        profile_id,
        profile,
        allowed,
        excluded,
        source_count,
    ) = prepare_authenticated_targets(
        project,
        "katana",
        run_id,
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

    options = {
        "template_source": template_source_option(),
        "severities": severities,
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
    }

    handoff = create_authenticated_handoff(
        project=project,
        source_engine="katana",
        source_run_id=run_id,
        destination_engine="nuclei",
        destination_profile="web-safe",
        profile_id=profile_id,
        allowed_targets=allowed,
        excluded_count=excluded,
        source_count=source_count,
        options=options,
    )

    payload = handoff_payload(
        options=options,
        handoff=handoff,
        source_engine="katana",
        source_run_id=run_id,
        profile_id=profile_id,
    )

    launch_and_attach(
        project=project,
        handoff=handoff,
        launcher=(launch_nuclei_authenticated_job),
        payload=payload,
    )

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )

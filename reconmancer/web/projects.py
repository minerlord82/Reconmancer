from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    redirect,
    request,
    url_for,
)

from reconmancer.core.project_lifecycle import (
    delete_project,
    prepare_new_project,
    suggested_slug,
)

from reconmancer.core.projects import (
    create_project,
)


HOME = Path("/opt/reconmancer")


projects_blueprint = Blueprint(
    "projects_workspace",
    __name__,
)


def _redirect_home(
    *,
    message: str | None = None,
    error: str | None = None,
):
    values = {}

    if message:
        values["message"] = message

    if error:
        values["error"] = error

    return redirect(
        url_for(
            "index",
            **values,
        )
    )


@projects_blueprint.route(
    "/projects/create/",
    methods=[
        "POST",
    ],
)
def project_create():
    name = request.form.get(
        "name",
        "",
    ).strip()

    if not name:
        return _redirect_home(error="Project name is required.")

    if len(name) > 120:
        return _redirect_home(error="Project name is too long.")

    slug = (
        request.form.get(
            "slug",
            "",
        )
        .strip()
        .lower()
    )

    if not slug:
        slug = suggested_slug(name)

    if not slug:
        return _redirect_home(
            error=("Could not generate a project slug. Enter one manually.")
        )

    try:
        disk_limit_gb = float(
            request.form.get(
                "disk_limit_gb",
                "10",
            )
        )
    except (
        TypeError,
        ValueError,
    ):
        disk_limit_gb = 10.0

    disk_limit_gb = max(
        1.0,
        min(
            disk_limit_gb,
            1000.0,
        ),
    )

    try:
        create_project(
            HOME,
            name,
            slug,
            disk_limit_gb=disk_limit_gb,
        )

        project = prepare_new_project(
            HOME,
            slug,
        )

    except FileExistsError:
        return _redirect_home(error=(f"A project named '{slug}' already exists."))

    except ValueError as exc:
        return _redirect_home(
            error=str(exc),
        )

    return redirect(
        url_for(
            "overview",
            slug=project["config"]["project"]["slug"],
        )
    )


@projects_blueprint.route(
    "/projects/<slug>/delete/",
    methods=[
        "POST",
    ],
)
def project_delete(
    slug: str,
):
    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    if confirmation != slug:
        abort(
            400,
            "Type the exact project slug to confirm deletion.",
        )

    try:
        result = delete_project(
            HOME,
            slug,
        )

    except FileNotFoundError:
        abort(404)

    except ValueError as exc:
        return _redirect_home(
            error=str(exc),
        )

    return _redirect_home(message=(f"Deleted project '{result['slug']}'."))

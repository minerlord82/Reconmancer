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
    create_profile,
    delete_profile,
)

from reconmancer.core.projects import (
    load_project,
)


HOME = Path("/opt/reconmancer")


auth_profiles_blueprint = Blueprint(
    "auth_profiles",
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


@auth_profiles_blueprint.route(
    "/p/<slug>/settings/auth/create/",
    methods=[
        "POST",
    ],
)
def create_auth_profile(
    slug: str,
):

    project = project_or_404(slug)

    try:
        profile = create_profile(
            project["root"],
            name=request.form.get(
                "name",
                "",
            ),
            domains_raw=request.form.get(
                "domains",
                "",
            ),
            headers_raw=request.form.get(
                "headers",
                "",
            ),
            cookie=request.form.get(
                "cookie",
                "",
            ),
            notes=request.form.get(
                "notes",
                "",
            ),
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message=(f"Authentication profile {profile['id']} created."),
        )
    )


@auth_profiles_blueprint.route(
    "/p/<slug>/settings/auth/<profile_id>/delete/",
    methods=[
        "POST",
    ],
)
def delete_auth_profile(
    slug: str,
    profile_id: str,
):

    project = project_or_404(slug)

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    if confirmation != profile_id:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error=("Authentication profile confirmation did not match."),
            )
        )

    try:
        delete_profile(
            project["root"],
            profile_id,
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message=(f"{profile_id} deleted."),
        )
    )

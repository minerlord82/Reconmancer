from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    url_for,
)

from reconmancer.core.project_lifecycle import (
    wipe_collected_data,
)

from reconmancer.core.projects import (
    load_project,
)

from reconmancer.core.storage_workspace import (
    build_storage_workspace,
    delete_artifact,
    delete_run,
    execute_maintenance,
    get_artifact,
    preview_maintenance,
    preview_run_cleanup,
)


HOME = Path("/opt/reconmancer")


storage_blueprint = Blueprint(
    "storage_workspace",
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


@storage_blueprint.route("/p/<slug>/storage/")
def storage_index(
    slug: str,
):

    project = project_or_404(slug)

    workspace = build_storage_workspace(project)

    return render_template(
        "storage.html",
        project=project,
        workspace=workspace,
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@storage_blueprint.route(
    "/p/<slug>/storage/wipe/",
    methods=[
        "POST",
    ],
)
def storage_wipe(
    slug: str,
):
    project = project_or_404(slug)

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    required = f"WIPE {slug}"

    if confirmation != required:
        abort(
            400,
            f"Type '{required}' exactly to confirm the wipe.",
        )

    try:
        result = wipe_collected_data(project)

    except ValueError as exc:
        return redirect(
            url_for(
                "storage_workspace.storage_index",
                slug=slug,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "storage_workspace.storage_index",
            slug=slug,
            message=(
                "Collected project data wiped. "
                f"Freed approximately {result['removed_bytes']} bytes. "
                "Project settings, targets.txt and auth profiles were preserved."
            ),
        )
    )


@storage_blueprint.route(
    "/p/<slug>/storage/run/<run_id>/preview/",
    methods=[
        "POST",
    ],
)
def storage_run_preview(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    preview = preview_run_cleanup(
        project["database"],
        project["root"],
        run_id,
    )

    if preview is None:
        abort(404)

    return render_template(
        "storage_cleanup.html",
        project=project,
        cleanup_type="run",
        preview=preview,
        run_id=run_id,
        artifact=None,
        maintenance=None,
    )


@storage_blueprint.route(
    "/p/<slug>/storage/run/<run_id>/delete/",
    methods=[
        "POST",
    ],
)
def storage_run_delete(
    slug: str,
    run_id: str,
):

    project = project_or_404(slug)

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    if confirmation != run_id:
        abort(
            400,
            ("Confirmation did not match the run ID."),
        )

    try:
        result = delete_run(
            project["database"],
            project["root"],
            run_id,
        )

    except ValueError as exc:
        abort(
            400,
            str(exc),
        )

    message = (
        f"Deleted {run_id}. "
        f"Removed approximately "
        f"{result['removed_bytes']} bytes "
        f"from run-owned files."
    )

    return redirect(
        url_for(
            "storage_workspace.storage_index",
            slug=slug,
            message=message,
        )
    )


@storage_blueprint.route(
    "/p/<slug>/storage/artifact/<hash_value>/preview/",
    methods=[
        "POST",
    ],
)
def storage_artifact_preview(
    slug: str,
    hash_value: str,
):

    project = project_or_404(slug)

    artifact = get_artifact(
        project["database"],
        hash_value,
    )

    if artifact is None:
        abort(404)

    return render_template(
        "storage_cleanup.html",
        project=project,
        cleanup_type="artifact",
        preview=None,
        run_id=None,
        artifact=artifact,
        maintenance=None,
    )


@storage_blueprint.route(
    "/p/<slug>/storage/artifact/<hash_value>/delete/",
    methods=[
        "POST",
    ],
)
def storage_artifact_delete(
    slug: str,
    hash_value: str,
):

    project = project_or_404(slug)

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    if confirmation != hash_value:
        abort(
            400,
            ("Confirmation did not match the artifact hash."),
        )

    try:
        result = delete_artifact(
            project["database"],
            project["root"],
            hash_value,
        )

    except ValueError as exc:
        abort(
            400,
            str(exc),
        )

    message = (
        "Deleted unreferenced artifact "
        f"{hash_value[:12]}… "
        f"({result['removed_bytes']} bytes)."
    )

    return redirect(
        url_for(
            "storage_workspace.storage_index",
            slug=slug,
            message=message,
        )
    )


@storage_blueprint.route(
    "/p/<slug>/storage/maintenance/<kind>/preview/",
    methods=[
        "POST",
    ],
)
def storage_maintenance_preview(
    slug: str,
    kind: str,
):

    project = project_or_404(slug)

    try:
        maintenance = preview_maintenance(
            project["database"],
            project["root"],
            kind,
        )

    except ValueError as exc:
        abort(
            400,
            str(exc),
        )

    return render_template(
        "storage_cleanup.html",
        project=project,
        cleanup_type="maintenance",
        preview=None,
        run_id=None,
        artifact=None,
        maintenance=maintenance,
    )


@storage_blueprint.route(
    "/p/<slug>/storage/maintenance/<kind>/execute/",
    methods=[
        "POST",
    ],
)
def storage_maintenance_execute(
    slug: str,
    kind: str,
):

    project = project_or_404(slug)

    confirmation = request.form.get(
        "confirm",
        "",
    ).strip()

    if confirmation != "CLEAN":
        abort(
            400,
            "Type CLEAN to confirm.",
        )

    try:
        result = execute_maintenance(
            project["database"],
            project["root"],
            kind,
        )

    except ValueError as exc:
        abort(
            400,
            str(exc),
        )

    message = (
        f"Maintenance cleanup complete. "
        f"Removed approximately "
        f"{result['removed_bytes']} bytes."
    )

    return redirect(
        url_for(
            "storage_workspace.storage_index",
            slug=slug,
            message=message,
        )
    )

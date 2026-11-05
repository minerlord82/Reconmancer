from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    render_template,
)

from reconmancer.core.projects import (
    load_project,
)

from reconmancer.core.runs_workspace import (
    build_runs_workspace,
)


HOME = Path("/opt/reconmancer")


runs_blueprint = Blueprint(
    "runs_workspace",
    __name__,
)


@runs_blueprint.route("/p/<slug>/runs/")
def runs_index(
    slug: str,
):

    try:
        project = load_project(
            HOME,
            slug,
        )

    except (
        ValueError,
        FileNotFoundError,
    ):
        abort(404)

    workspace = build_runs_workspace(
        project["database"],
        limit=300,
    )

    return render_template(
        "runs.html",
        project=project,
        workspace=workspace,
    )

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, render_template, request

from reconmancer.core.analysis import (
    list_endpoint_clusters,
    list_query_parameters,
    refresh_url_analysis,
)
from reconmancer.core.projects import load_project

HOME = Path("/opt/reconmancer")
analysis_blueprint = Blueprint("analysis_workspace", __name__)


def project_or_404(slug: str):
    try:
        return load_project(HOME, slug)
    except (ValueError, FileNotFoundError):
        abort(404)


def int_arg(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


@analysis_blueprint.route("/p/<slug>/analysis/")
def analysis_index(slug: str):
    project = project_or_404(slug)
    refresh = refresh_url_analysis(project["database"], batch_size=1000, max_batches=25)
    clusters = list_endpoint_clusters(
        project["database"],
        query=request.args.get("cluster_q", "").strip()[:500],
        minimum_variants=max(1, int_arg("min_variants", 2)),
        page=max(1, int_arg("cluster_page", 1)),
        per_page=100,
    )
    parameters = list_query_parameters(
        project["database"],
        query=request.args.get("param_q", "").strip()[:500],
        kind=request.args.get("param_kind", "").strip().lower(),
        page=max(1, int_arg("param_page", 1)),
        per_page=100,
    )
    return render_template(
        "analysis.html",
        project=project,
        refresh=refresh,
        clusters=clusters,
        parameters=parameters,
        filters={
            "cluster_q": request.args.get("cluster_q", "").strip()[:500],
            "min_variants": max(1, int_arg("min_variants", 2)),
            "param_q": request.args.get("param_q", "").strip()[:500],
            "param_kind": request.args.get("param_kind", "").strip().lower(),
        },
    )

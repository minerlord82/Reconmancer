from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, render_template, request, send_file

from reconmancer.core.projects import load_project
from reconmancer.core.traffic_evidence import (
    get_object_path,
    get_traffic_evidence,
    list_traffic_evidence,
)

HOME = Path("/opt/reconmancer")
traffic_evidence_blueprint = Blueprint("traffic_evidence", __name__)


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


@traffic_evidence_blueprint.route("/p/<slug>/evidence/")
def evidence_index(slug: str):
    project = project_or_404(slug)
    engine = request.args.get("engine", "").strip().lower()
    if engine not in {"", "httpx", "katana", "nuclei"}:
        engine = ""
    result = list_traffic_evidence(
        project["database"],
        engine=engine,
        run_id=request.args.get("run_id", "").strip()[:100],
        query=request.args.get("q", "").strip()[:500],
        page=max(1, int_arg("page", 1)),
        per_page=100,
    )
    return render_template(
        "traffic_evidence.html",
        project=project,
        evidence=result,
        filters={
            "engine": engine,
            "run_id": request.args.get("run_id", "").strip()[:100],
            "q": request.args.get("q", "").strip()[:500],
        },
    )


@traffic_evidence_blueprint.route("/p/<slug>/evidence/<int:evidence_id>/<side>/")
def evidence_content(slug: str, evidence_id: int, side: str):
    if side not in {"request", "response"}:
        abort(404)
    project = project_or_404(slug)
    row = get_traffic_evidence(project["database"], evidence_id)
    if row is None:
        abort(404)
    digest = row.get(f"{side}_hash")
    if not digest:
        abort(404)
    path = get_object_path(
        db_path=project["database"],
        project_root=project["root"],
        object_hash=digest,
    )
    if path is None:
        abort(404)
    return send_file(path, mimetype="text/plain", conditional=True)

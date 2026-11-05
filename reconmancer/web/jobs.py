from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint, abort, redirect, render_template, request, url_for

from reconmancer.core.jobs import job_health, list_jobs, recover_stale_jobs
from reconmancer.core.projects import load_project
from reconmancer.core.scan_dispatch import retry_job

HOME = Path("/opt/reconmancer")
jobs_blueprint = Blueprint("jobs_workspace", __name__)


def project_or_404(slug: str):
    try:
        return load_project(HOME, slug)
    except (ValueError, FileNotFoundError):
        abort(404)


@jobs_blueprint.route("/p/<slug>/jobs/")
def jobs_index(slug: str):
    project = project_or_404(slug)
    recovery = recover_stale_jobs(project["database"])
    status = request.args.get("status", "").strip().lower()
    if status not in {"", "queued", "running", "completed", "failed", "interrupted"}:
        status = ""
    items = list_jobs(project["database"], status=status, limit=500)
    for item in items:
        item["health"] = job_health(item)
        try:
            item["payload"] = json.loads(item.get("payload_json") or "{}")
        except json.JSONDecodeError:
            item["payload"] = {}
    return render_template(
        "jobs.html",
        project=project,
        jobs=items,
        status=status,
        recovery=recovery,
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@jobs_blueprint.route("/p/<slug>/jobs/recover/", methods=["POST"])
def jobs_recover(slug: str):
    project = project_or_404(slug)
    result = recover_stale_jobs(project["database"])
    return redirect(
        url_for(
            "jobs_workspace.jobs_index",
            slug=slug,
            message=f"Recovery checked {result['checked']} job(s); interrupted {result['interrupted']}.",
        )
    )


@jobs_blueprint.route("/p/<slug>/jobs/<job_id>/retry/", methods=["POST"])
def jobs_retry(slug: str, job_id: str):
    project = project_or_404(slug)
    try:
        new_job_id = retry_job(project, job_id)
    except ValueError as exc:
        return redirect(url_for("jobs_workspace.jobs_index", slug=slug, error=str(exc)))
    return redirect(
        url_for(
            "jobs_workspace.jobs_index",
            slug=slug,
            message=f"Retry launched as {new_job_id}.",
        )
    )

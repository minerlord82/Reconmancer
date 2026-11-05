from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, redirect, request

from reconmancer.core.auth_profiles import get_profile, profile_applies_to_target
from reconmancer.core.auth_runtime import profile_has_credentials
from reconmancer.core.findings_workspace import get_source_record
from reconmancer.core.handoffs import (
    MAX_HANDOFF_TARGETS,
    attach_destination_job,
    create_handoff,
    mark_handoff_failed,
)
from reconmancer.core.projects import load_project
from reconmancer.core.scan_dispatch import dispatch_scan_job
from reconmancer.core.settings_workspace import get_project_settings
from reconmancer.core.source_browser import export_filtered_sources

HOME = Path("/opt/reconmancer")
selection_handoffs_blueprint = Blueprint("selection_handoffs", __name__)
VALID_ENGINES = {"httpx", "katana", "nuclei"}


def project_or_404(slug: str):
    try:
        return load_project(HOME, slug)
    except (ValueError, FileNotFoundError):
        abort(404)


def bool_form(name: str) -> bool:
    return request.form.get(name) in {"1", "true", "on", "yes"}


def _source_from_ref(db_path: Path, value: str) -> dict | None:
    parts = value.split("|", 2)
    if len(parts) != 3:
        return None
    engine, run_id, record_text = parts
    if engine not in VALID_ENGINES:
        return None
    try:
        record_id = int(record_text)
    except ValueError:
        return None
    source = get_source_record(db_path, engine, run_id, record_id)
    if source is None or not source.get("url"):
        return None
    url = str(source["url"]).strip()
    if not url.startswith(("http://", "https://")):
        return None
    return {
        "target": url,
        "source_engine": engine,
        "source_run_id": run_id,
        "source_record_id": record_id,
        "provenance": {
            "host": source.get("host"),
            "title": source.get("title"),
            "summary": source.get("summary"),
            "severity": source.get("severity"),
            "context": source.get("context"),
            "reason": "selected_observation",
        },
    }


def _selected_targets(project: dict) -> list[dict]:
    output = []
    for value in request.form.getlist("source_ref")[:MAX_HANDOFF_TARGETS]:
        source = _source_from_ref(project["database"], value)
        if source:
            output.append(source)
    return output


def _filtered_targets(project: dict) -> list[dict]:
    rows = export_filtered_sources(
        project["database"],
        engine=request.form.get("filter_engine", "all"),
        status=request.form.get("filter_status", ""),
        interesting=bool_form("filter_interesting"),
        severity=request.form.get("filter_severity", ""),
        context=request.form.get("filter_context", "all"),
        host=request.form.get("filter_host", ""),
        query=request.form.get("filter_q", ""),
        template_id=request.form.get("filter_template_id", ""),
        pinned_only=bool_form("filter_pinned"),
        limit=MAX_HANDOFF_TARGETS,
    )
    output = []
    for source in rows:
        url = str(source.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        output.append(
            {
                "target": url,
                "source_engine": source["engine"],
                "source_run_id": source["run_id"],
                "source_record_id": source["record_id"],
                "provenance": {
                    "host": source.get("host"),
                    "title": source.get("title"),
                    "summary": source.get("summary"),
                    "status_code": source.get("status_code"),
                    "severity": source.get("severity"),
                    "context": source.get("context"),
                    "reason": "filtered_observation",
                },
            }
        )
    return output


def nuclei_template_source() -> str:
    value = request.form.get("template_source", "default").strip().lower()
    if value not in {"default", "projectdiscovery"}:
        return "default"
    return value


def _destination_options(project: dict, engine: str, authenticated: bool) -> dict:
    defaults = get_project_settings(project)[engine]
    options = dict(defaults)
    if engine == "katana" and authenticated:
        options["no_scope"] = False
    if engine == "nuclei":
        options["template_source"] = nuclei_template_source()
        if authenticated:
            options["no_interactsh"] = True
    return options


@selection_handoffs_blueprint.route(
    "/p/<slug>/handoff-selection/",
    methods=["POST"],
)
def handoff_selection(slug: str):
    project = project_or_404(slug)
    destination = request.form.get("destination_engine", "").strip().lower()
    if destination not in VALID_ENGINES:
        abort(400, "Invalid destination engine.")

    mode = request.form.get("mode", "selected")
    if mode == "filtered":
        targets = _filtered_targets(project)
        source_engine = "filtered"
        source_run_id = "workspace"
    else:
        targets = _selected_targets(project)
        source_engine = request.form.get("source_engine", "selection") or "selection"
        source_run_id = request.form.get("source_run_id", "mixed") or "mixed"

    if not targets:
        abort(400, "No eligible HTTP(S) targets were selected.")

    auth_profile_id = request.form.get("auth_profile_id", "").strip() or None
    excluded = 0
    if auth_profile_id:
        try:
            profile = get_profile(project["root"], auth_profile_id)
        except ValueError:
            profile = None
        if profile is None or not profile_has_credentials(profile):
            abort(400, "Authentication profile is invalid or has no credentials.")
        allowed = []
        for item in targets:
            if profile_applies_to_target(profile, item["target"]):
                allowed.append(item)
            else:
                excluded += 1
        targets = allowed
        if not targets:
            abort(400, "No selected targets exactly match the authentication profile.")

    options = _destination_options(project, destination, bool(auth_profile_id))
    options.update(
        {
            "selection_mode": mode,
            "excluded_by_auth_scope": excluded,
            "auth_profile_id": auth_profile_id,
        }
    )
    destination_profile = (
        options.get("profile")
        if destination == "katana"
        else ("web-safe" if destination == "nuclei" else "full")
    )

    handoff = create_handoff(
        db_path=project["database"],
        project_root=project["root"],
        source_engine=source_engine,
        source_run_id=source_run_id,
        destination_engine=destination,
        destination_profile=destination_profile,
        targets=targets,
        options=options,
    )

    payload = {
        **options,
        "target_count": handoff["target_count"],
        "source_handoff_id": handoff["id"],
        "source_engine": source_engine,
        "source_run_id": source_run_id,
    }

    try:
        job_id = dispatch_scan_job(
            project,
            engine=destination,
            payload=payload,
            target_file=handoff["target_file"],
            auth_profile_id=auth_profile_id,
        )
        attach_destination_job(project["database"], handoff["id"], job_id)
    except Exception as exc:
        mark_handoff_failed(project["database"], handoff["id"], str(exc))
        raise

    return redirect(f"/p/{slug}/{destination}/")

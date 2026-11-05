from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, redirect, render_template, request, url_for

from reconmancer.core.auth_profiles import list_profiles
from reconmancer.core.compression import compress_eligible_project
from reconmancer.core.projects import load_project
from reconmancer.core.nuclei_templates import update_projectdiscovery_templates
from reconmancer.core.tool_updates import update_projectdiscovery_tool
from reconmancer.core.settings_workspace import (
    VALID_COMPRESSION_ALGORITHMS,
    VALID_KATANA_PROFILES,
    VALID_NUCLEI_SEVERITIES,
    VALID_PAGE_LOAD_STRATEGIES,
    build_settings_workspace,
    get_project_settings,
    save_project_settings,
)

HOME = Path("/opt/reconmancer")
settings_blueprint = Blueprint("settings_workspace", __name__)


def project_or_404(slug: str):
    try:
        return load_project(HOME, slug)
    except (ValueError, FileNotFoundError):
        abort(404)


def integer_value(name: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(request.form.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def float_value(name: str, *, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(request.form.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def checkbox(name: str) -> bool:
    return request.form.get(name) == "1"


@settings_blueprint.route("/p/<slug>/settings/")
def settings_index(slug: str):
    project = project_or_404(slug)
    return render_template(
        "settings.html",
        project=project,
        workspace=build_settings_workspace(HOME, project),
        auth_profiles=list_profiles(project["root"]),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@settings_blueprint.route("/p/<slug>/settings/save/", methods=["POST"])
def settings_save(slug: str):
    project = project_or_404(slug)
    current = get_project_settings(project)

    katana_profile = request.form.get("katana_profile", current["katana"]["profile"])
    if katana_profile not in VALID_KATANA_PROFILES:
        katana_profile = "standard"

    strategy = request.form.get(
        "katana_page_load_strategy",
        current["katana"]["page_load_strategy"],
    )
    if strategy not in VALID_PAGE_LOAD_STRATEGIES:
        strategy = "heuristic"

    severities = []
    for value in request.form.getlist("nuclei_severity"):
        lowered = value.strip().lower()
        if lowered in VALID_NUCLEI_SEVERITIES and lowered not in severities:
            severities.append(lowered)
    if not severities:
        severities = ["info", "low", "medium", "high", "critical"]

    algorithm = request.form.get(
        "compression_algorithm",
        current["compression"]["algorithm"],
    )
    if algorithm not in VALID_COMPRESSION_ALGORITHMS:
        algorithm = "zstd"

    settings = {
        "disk_limit_gb": float_value(
            "disk_limit_gb", default=10.0, minimum=1.0, maximum=1000.0
        ),
        "httpx": {
            "rate_limit": integer_value(
                "httpx_rate_limit", default=10, minimum=1, maximum=1000
            ),
            "redirect_depth": integer_value(
                "httpx_redirect_depth", default=10, minimum=0, maximum=50
            ),
            "screenshots": checkbox("httpx_screenshots"),
        },
        "katana": {
            "profile": katana_profile,
            "depth": integer_value("katana_depth", default=3, minimum=1, maximum=10),
            "rate_limit": integer_value(
                "katana_rate_limit", default=20, minimum=1, maximum=500
            ),
            "concurrency": integer_value(
                "katana_concurrency", default=5, minimum=1, maximum=50
            ),
            "parallelism": integer_value(
                "katana_parallelism", default=2, minimum=1, maximum=20
            ),
            "page_load_strategy": strategy,
            "js_crawl": checkbox("katana_js_crawl"),
            "known_files": checkbox("katana_known_files"),
            "form_extraction": checkbox("katana_form_extraction"),
            "tech_detect": checkbox("katana_tech_detect"),
            "no_scope": checkbox("katana_no_scope"),
        },
        "nuclei": {
            "severities": severities,
            "tags": request.form.get("nuclei_tags", "")[:500].strip(),
            "exclude_tags": request.form.get(
                "nuclei_exclude_tags", "dos,fuzz,bruteforce"
            )[:500].strip(),
            "rate_limit": integer_value(
                "nuclei_rate_limit", default=10, minimum=1, maximum=500
            ),
            "concurrency": integer_value(
                "nuclei_concurrency", default=5, minimum=1, maximum=50
            ),
            "bulk_size": integer_value(
                "nuclei_bulk_size", default=5, minimum=1, maximum=50
            ),
            "no_interactsh": checkbox("nuclei_no_interactsh"),
            "allow_headless": checkbox("nuclei_allow_headless"),
        },
        "compression": {
            "enabled": checkbox("compression_enabled"),
            "algorithm": algorithm,
            "minimum_age_days": float_value(
                "compression_minimum_age_days", default=7.0, minimum=0.0, maximum=3650.0
            ),
            "minimum_size_mb": float_value(
                "compression_minimum_size_mb", default=1.0, minimum=0.0, maximum=10240.0
            ),
            "max_files_per_pass": integer_value(
                "compression_max_files_per_pass", default=50, minimum=1, maximum=10000
            ),
        },
    }

    save_project_settings(project, settings)
    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message="Project settings saved.",
        )
    )


@settings_blueprint.route("/p/<slug>/settings/compress-now/", methods=["POST"])
def settings_compress_now(slug: str):
    project = project_or_404(slug)
    settings = get_project_settings(project)["compression"]
    summary = compress_eligible_project(
        project["root"],
        enabled=True,
        algorithm=settings["algorithm"],
        minimum_age_days=settings["minimum_age_days"],
        minimum_size_mb=settings["minimum_size_mb"],
        max_files=settings["max_files_per_pass"],
    )
    if summary["errors"]:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error="; ".join(summary["errors"][:3]),
            )
        )
    saved_mb = summary["saved_bytes"] / (1024 * 1024)
    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message=(
                f"Compressed {summary['compressed']} file(s); saved {saved_mb:.2f} MB."
            ),
        )
    )


@settings_blueprint.route(
    "/p/<slug>/settings/nuclei-templates/update/",
    methods=["POST"],
)
def settings_update_nuclei_templates(slug: str):
    project_or_404(slug)

    try:
        result = update_projectdiscovery_templates(HOME)
    except RuntimeError as exc:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error=str(exc),
            )
        )

    before = result.get("before", "Unknown")
    after = result.get("after", "Unknown")

    if before == after:
        message = f"nuclei-templates (ProjectDiscovery) is up to date: {after}"
    else:
        message = f"nuclei-templates (ProjectDiscovery) updated: {before} → {after}"

    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message=message,
        )
    )


@settings_blueprint.route(
    "/p/<slug>/settings/tools/<tool_name>/update/",
    methods=["POST"],
)
def settings_update_tool(slug: str, tool_name: str):
    project_or_404(slug)

    try:
        result = update_projectdiscovery_tool(
            HOME,
            tool_name,
        )
    except RuntimeError as exc:
        return redirect(
            url_for(
                "settings_workspace.settings_index",
                slug=slug,
                error=str(exc),
            )
        )

    before = result.get(
        "before",
        "Unknown",
    )

    after = result.get(
        "after",
        "Unknown",
    )

    label = result.get(
        "tool",
        tool_name,
    ).upper()

    if before == after:
        message = f"{label} is already up to date: {after}"
    else:
        message = f"{label} updated: {before} → {after}"

    return redirect(
        url_for(
            "settings_workspace.settings_index",
            slug=slug,
            message=message,
        )
    )

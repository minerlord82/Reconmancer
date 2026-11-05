from __future__ import annotations

import json
import math
import subprocess
import sys
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from reconmancer.core.database import (
    get_counts,
)

from reconmancer.core.handoffs import (
    attach_destination_job,
    collect_httpx_targets,
    collect_katana_targets,
    create_handoff,
    list_handoffs,
    mark_handoff_failed,
)

from reconmancer.core.jobs import (
    create_job,
    list_engine_jobs,
    recover_projects_on_startup,
    set_job_failed,
)

from reconmancer.core.scan_dispatch import dispatch_scan_job

from reconmancer.core.projects import (
    directory_size,
    list_projects,
    load_project,
)

from reconmancer.engines.httpx.queries import (
    count_run_observations as count_httpx_observations,
    get_httpx_run,
    get_run_stats as get_httpx_run_stats,
    latest_httpx_run,
    list_httpx_runs,
    list_run_observations as list_httpx_observations,
    list_run_redirects,
)

from reconmancer.engines.httpx.screenshots import (
    get_screenshot_path,
    get_thumbnail_path,
)

from reconmancer.engines.katana.queries import (
    count_run_observations as count_katana_observations,
    get_katana_run,
    get_run_stats as get_katana_run_stats,
    latest_katana_run,
    list_katana_runs,
    list_run_groups,
    list_run_observations as list_katana_observations,
)

from reconmancer.engines.katana.schema import (
    ensure_katana_schema,
)

from reconmancer.engines.nuclei.queries import (
    count_run_findings,
    get_nuclei_run,
    get_run_stats as get_nuclei_run_stats,
    latest_nuclei_run,
    list_nuclei_runs,
    list_run_findings,
)

from reconmancer.engines.nuclei.schema import (
    ensure_nuclei_schema,
)

from reconmancer.web import (
    register_web_blueprints,
)


HOME = Path("/opt/reconmancer")


app = Flask(
    __name__,
    template_folder="web/templates",
    static_folder="web/static",
)


register_web_blueprints(app)

# Recover jobs whose detached workers disappeared during a VPS/app restart.
# Live workers with a valid PID are left untouched.
recover_projects_on_startup(HOME)


def human_bytes(
    value: int,
) -> str:

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    size = float(value)

    for unit in units:
        if size < 1024:
            return f"{size:.1f} {unit}"

        size /= 1024

    return f"{size:.1f} PB"


app.jinja_env.filters["human_bytes"] = human_bytes


def get_project_or_404(
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


def parse_job_payload(
    job: dict,
) -> dict:

    raw = job.get("payload_json") or "{}"

    try:
        return json.loads(raw)

    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return {}


def collect_uploaded_targets() -> tuple[
    list[str],
    str | None,
]:

    sources = []

    uploaded_file = request.files.get("targets_file")

    uploaded_filename = None

    if uploaded_file and uploaded_file.filename:
        uploaded_filename = uploaded_file.filename.strip()

        if not (uploaded_filename.lower().endswith(".txt")):
            abort(
                400,
                ("Target upload must be a .txt file."),
            )

        raw_data = uploaded_file.read()

        if len(raw_data) > (10 * 1024 * 1024):
            abort(
                400,
                ("Target file is larger than 10 MB."),
            )

        try:
            text_data = raw_data.decode("utf-8")

        except UnicodeDecodeError:
            text_data = raw_data.decode(
                "utf-8",
                errors="ignore",
            )

        sources.append(text_data)

    pasted = request.form.get(
        "targets",
        "",
    )

    if pasted.strip():
        sources.append(pasted)

    if not sources:
        abort(
            400,
            ("Upload a targets.txt file or enter targets."),
        )

    targets = []

    seen = set()

    for source in sources:
        for line in source.splitlines():
            value = line.strip()

            if not value:
                continue

            if value.startswith("#"):
                continue

            if value in seen:
                continue

            seen.add(value)

            targets.append(value)

    if not targets:
        abort(
            400,
            "No valid targets found.",
        )

    if len(targets) > 100000:
        abort(
            400,
            ("Maximum 100,000 targets per job."),
        )

    return (
        targets,
        uploaded_filename,
    )


def integer_form_option(
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


def template_source_form_option() -> str:
    value = request.form.get("template_source", "default").strip().lower()
    if value not in {"default", "projectdiscovery"}:
        return "default"
    return value


def write_job_targets(
    project: dict,
    job_id: str,
    targets: list[str],
) -> Path:

    directory = project["root"] / "input" / "jobs" / job_id

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    target_file = directory / "targets.txt"

    target_file.write_text(
        "\n".join(targets) + "\n",
        encoding="utf-8",
    )

    return target_file


def spawn_background_job(
    project: dict,
    job_id: str,
    command: list[str],
) -> None:

    log_directory = project["root"] / "logs" / "jobs"

    log_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path = log_directory / f"{job_id}.log"

    try:
        with log_path.open(
            "a",
            encoding="utf-8",
        ) as log_handle:
            subprocess.Popen(
                command,
                cwd=str(HOME),
                stdout=(log_handle),
                stderr=(subprocess.STDOUT),
                start_new_session=True,
            )

    except Exception:
        set_job_failed(
            project["database"],
            job_id,
        )

        raise


def launch_httpx_job(
    project: dict,
    payload: dict,
    *,
    targets: list[str] | None = None,
    target_file: Path | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="httpx",
        payload=payload,
        targets=targets,
        target_file=target_file,
    )


def launch_katana_job(
    project: dict,
    payload: dict,
    *,
    targets: list[str] | None = None,
    target_file: Path | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="katana",
        payload=payload,
        targets=targets,
        target_file=target_file,
    )


def launch_nuclei_job(
    project: dict,
    payload: dict,
    *,
    targets: list[str] | None = None,
    target_file: Path | None = None,
) -> str:
    return dispatch_scan_job(
        project,
        engine="nuclei",
        payload=payload,
        targets=targets,
        target_file=target_file,
    )


@app.route("/")
def index():

    return render_template(
        "index.html",
        projects=list_projects(HOME),
        project=None,
    )


@app.route("/p/<slug>/")
def overview(
    slug: str,
):

    project = get_project_or_404(slug)

    counts = get_counts(project["database"])

    used_bytes = directory_size(project["root"])

    disk_limit_gb = float(
        project["config"]
        .get(
            "resources",
            {},
        )
        .get(
            "disk_limit_gb",
            10.0,
        )
    )

    limit_bytes = int(disk_limit_gb * 1024 * 1024 * 1024)

    percentage = 0.0

    if limit_bytes:
        percentage = min(
            100.0,
            (used_bytes / limit_bytes) * 100.0,
        )

    return render_template(
        "overview.html",
        project=project,
        counts=counts,
        used_bytes=used_bytes,
        limit_bytes=limit_bytes,
        storage_percentage=(percentage),
    )


# HTTPX


@app.route("/p/<slug>/httpx/")
def httpx_index(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    runs = list_httpx_runs(db)

    latest = latest_httpx_run(db)

    latest_stats = (
        get_httpx_run_stats(
            db,
            latest["id"],
        )
        if latest
        else None
    )

    jobs = list_engine_jobs(
        db,
        "httpx",
        limit=20,
    )

    for job in jobs:
        payload = parse_job_payload(job)

        job["target_count"] = payload.get(
            "target_count",
            0,
        )

        job["screenshots_requested"] = bool(
            payload.get(
                "screenshots",
                False,
            )
        )

        job["observations"] = 0

        job["redirects"] = 0

        job["screenshots"] = 0

        if job.get("run_id"):
            stats = get_httpx_run_stats(
                db,
                job["run_id"],
            )

            job["observations"] = stats["total"]

            job["redirects"] = stats["redirects"]

            job["screenshots"] = stats["screenshots"]

    return render_template(
        "httpx.html",
        project=project,
        runs=runs,
        latest=latest,
        latest_stats=latest_stats,
        jobs=jobs,
    )


@app.route("/p/<slug>/httpx/run/<run_id>/")
def httpx_run(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    run = get_httpx_run(
        db,
        run_id,
    )

    if run is None:
        abort(404)

    try:
        page = int(
            request.args.get(
                "page",
                1,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        page = 1

    page = max(
        1,
        page,
    )

    per_page = 100

    total = count_httpx_observations(
        db,
        run_id,
    )

    pages = max(
        1,
        math.ceil(total / per_page),
    )

    page = min(
        page,
        pages,
    )

    return render_template(
        "httpx_run.html",
        project=project,
        run=run,
        observations=list_httpx_observations(
            db,
            run_id,
            page=page,
            per_page=per_page,
        ),
        redirects=list_run_redirects(
            db,
            run_id,
        ),
        stats=get_httpx_run_stats(
            db,
            run_id,
        ),
        handoffs=list_handoffs(
            db,
            source_engine="httpx",
            source_run_id=run_id,
            limit=50,
        ),
        page=page,
        pages=pages,
        total=total,
    )


@app.route(
    "/p/<slug>/httpx/new/",
    methods=[
        "POST",
    ],
)
def httpx_new_scan(
    slug: str,
):

    project = get_project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_uploaded_targets()

    payload = {
        "target_count": len(targets),
        "rate_limit": (
            integer_form_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=1000,
            )
        ),
        "redirect_depth": (
            integer_form_option(
                "redirect_depth",
                default=10,
                minimum=0,
                maximum=50,
            )
        ),
        "screenshots": (request.form.get("screenshots") == "1"),
        "context": "anonymous",
        "uploaded_file": filename,
    }

    launch_httpx_job(
        project,
        payload,
        targets=targets,
    )

    return redirect(
        url_for(
            "httpx_index",
            slug=slug,
        )
    )


@app.route("/p/<slug>/httpx/status.json")
def httpx_status(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    output = []

    for job in list_engine_jobs(
        db,
        "httpx",
        limit=20,
    ):
        payload = parse_job_payload(job)

        item = {
            "id": job["id"],
            "status": job["status"],
            "run_id": job["run_id"],
            "target_count": (
                payload.get(
                    "target_count",
                    0,
                )
            ),
            "screenshots_requested": (
                bool(
                    payload.get(
                        "screenshots",
                        False,
                    )
                )
            ),
            "observations": 0,
            "redirects": 0,
            "screenshots": 0,
        }

        if job.get("run_id"):
            stats = get_httpx_run_stats(
                db,
                job["run_id"],
            )

            item["observations"] = stats["total"]

            item["redirects"] = stats["redirects"]

            item["screenshots"] = stats["screenshots"]

        output.append(item)

    return jsonify({"jobs": output})


@app.route("/p/<slug>/httpx/screenshot/<hash_value>/")
def httpx_screenshot(
    slug: str,
    hash_value: str,
):

    project = get_project_or_404(slug)

    path = get_screenshot_path(
        project_root=project["root"],
        db_path=project["database"],
        screenshot_hash=(hash_value),
    )

    if path is None:
        abort(404)

    return send_file(
        path,
        conditional=True,
    )


@app.route("/p/<slug>/httpx/screenshot/<hash_value>/thumb/")
def httpx_screenshot_thumb(
    slug: str,
    hash_value: str,
):

    project = get_project_or_404(slug)

    path = get_thumbnail_path(
        project_root=project["root"],
        db_path=project["database"],
        screenshot_hash=(hash_value),
    )

    if path is None:
        abort(404)

    return send_file(
        path,
        conditional=True,
    )


# KATANA


@app.route("/p/<slug>/katana/")
def katana_index(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    ensure_katana_schema(db)

    runs = list_katana_runs(db)

    latest = latest_katana_run(db)

    latest_stats = (
        get_katana_run_stats(
            db,
            latest["id"],
        )
        if latest
        else None
    )

    jobs = list_engine_jobs(
        db,
        "katana",
        limit=20,
    )

    for job in jobs:
        payload = parse_job_payload(job)

        job["target_count"] = payload.get(
            "target_count",
            0,
        )

        job["profile"] = payload.get(
            "profile",
            "standard",
        )

        job["results"] = 0

        job["unique_urls"] = 0

        job["xhr"] = 0

        if job.get("run_id"):
            stats = get_katana_run_stats(
                db,
                job["run_id"],
            )

            job["results"] = stats["total"]

            job["unique_urls"] = stats["unique_urls"]

            job["xhr"] = stats["xhr"]

    return render_template(
        "katana.html",
        project=project,
        runs=runs,
        latest=latest,
        latest_stats=latest_stats,
        jobs=jobs,
    )


@app.route("/p/<slug>/katana/run/<run_id>/")
def katana_run(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    run = get_katana_run(
        db,
        run_id,
    )

    if run is None:
        abort(404)

    try:
        page = int(
            request.args.get(
                "page",
                1,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        page = 1

    page = max(
        1,
        page,
    )

    per_page = 100

    total = count_katana_observations(
        db,
        run_id,
    )

    pages = max(
        1,
        math.ceil(total / per_page),
    )

    page = min(
        page,
        pages,
    )

    return render_template(
        "katana_run.html",
        project=project,
        run=run,
        observations=list_katana_observations(
            db,
            run_id,
            page=page,
            per_page=per_page,
        ),
        groups=list_run_groups(
            db,
            run_id,
            limit=500,
        ),
        stats=get_katana_run_stats(
            db,
            run_id,
        ),
        handoffs=list_handoffs(
            db,
            source_engine="katana",
            source_run_id=run_id,
            limit=50,
        ),
        page=page,
        pages=pages,
        total=total,
    )


@app.route(
    "/p/<slug>/katana/new/",
    methods=[
        "POST",
    ],
)
def katana_new_scan(
    slug: str,
):

    project = get_project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_uploaded_targets()

    profile = request.form.get(
        "profile",
        "standard",
    )

    if profile not in {
        "standard",
        "headless",
        "deep",
    }:
        profile = "standard"

    strategy = request.form.get(
        "page_load_strategy",
        "heuristic",
    )

    if strategy not in {
        "heuristic",
        "load",
        "domcontentloaded",
        "networkidle",
        "none",
    }:
        strategy = "heuristic"

    payload = {
        "target_count": len(targets),
        "profile": profile,
        "depth": (
            integer_form_option(
                "depth",
                default=3,
                minimum=1,
                maximum=10,
            )
        ),
        "rate_limit": (
            integer_form_option(
                "rate_limit",
                default=20,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_form_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "parallelism": (
            integer_form_option(
                "parallelism",
                default=2,
                minimum=1,
                maximum=20,
            )
        ),
        "page_load_strategy": (strategy),
        "js_crawl": (request.form.get("js_crawl") == "1"),
        "known_files": (request.form.get("known_files") == "1"),
        "form_extraction": (request.form.get("form_extraction") == "1"),
        "tech_detect": (request.form.get("tech_detect") == "1"),
        "no_scope": (request.form.get("no_scope") == "1"),
        "uploaded_file": (filename),
        "context": "anonymous",
    }

    launch_katana_job(
        project,
        payload,
        targets=targets,
    )

    return redirect(
        url_for(
            "katana_index",
            slug=slug,
        )
    )


@app.route("/p/<slug>/katana/status.json")
def katana_status(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    output = []

    for job in list_engine_jobs(
        db,
        "katana",
        limit=20,
    ):
        payload = parse_job_payload(job)

        item = {
            "id": job["id"],
            "status": job["status"],
            "run_id": job["run_id"],
            "profile": (
                payload.get(
                    "profile",
                    "standard",
                )
            ),
            "target_count": (
                payload.get(
                    "target_count",
                    0,
                )
            ),
            "results": 0,
            "unique_urls": 0,
            "xhr": 0,
        }

        if job.get("run_id"):
            stats = get_katana_run_stats(
                db,
                job["run_id"],
            )

            item["results"] = stats["total"]

            item["unique_urls"] = stats["unique_urls"]

            item["xhr"] = stats["xhr"]

        output.append(item)

    return jsonify({"jobs": output})


# HTTPX -> KATANA


@app.route(
    "/p/<slug>/httpx/run/<run_id>/send/katana/",
    methods=[
        "POST",
    ],
)
def httpx_send_to_katana(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    if (
        get_httpx_run(
            db,
            run_id,
        )
        is None
    ):
        abort(404)

    source_targets = collect_httpx_targets(
        db,
        run_id,
    )

    if not source_targets:
        abort(
            400,
            ("This HTTPX run has no URLs to hand off."),
        )

    profile = request.form.get(
        "profile",
        "standard",
    )

    if profile not in {
        "standard",
        "headless",
        "deep",
    }:
        profile = "standard"

    strategy = request.form.get(
        "page_load_strategy",
        "heuristic",
    )

    if strategy not in {
        "heuristic",
        "load",
        "domcontentloaded",
        "networkidle",
        "none",
    }:
        strategy = "heuristic"

    options = {
        "profile": profile,
        "depth": (
            integer_form_option(
                "depth",
                default=3,
                minimum=1,
                maximum=10,
            )
        ),
        "rate_limit": (
            integer_form_option(
                "rate_limit",
                default=20,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_form_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "parallelism": (
            integer_form_option(
                "parallelism",
                default=2,
                minimum=1,
                maximum=20,
            )
        ),
        "page_load_strategy": (strategy),
        "js_crawl": (request.form.get("js_crawl") == "1"),
        "known_files": (request.form.get("known_files") == "1"),
        "form_extraction": (request.form.get("form_extraction") == "1"),
        "tech_detect": (request.form.get("tech_detect") == "1"),
        "no_scope": (request.form.get("no_scope") == "1"),
    }

    handoff = create_handoff(
        db_path=db,
        project_root=project["root"],
        source_engine="httpx",
        source_run_id=run_id,
        destination_engine="katana",
        destination_profile=profile,
        targets=source_targets,
        options=options,
    )

    payload = {
        **options,
        "target_count": (handoff["target_count"]),
        "source_handoff_id": (handoff["id"]),
        "source_engine": "httpx",
        "source_run_id": run_id,
        "context": "anonymous",
    }

    try:
        job_id = launch_katana_job(
            project,
            payload,
            target_file=handoff["target_file"],
        )

        attach_destination_job(
            db,
            handoff["id"],
            job_id,
        )

    except Exception as exc:
        mark_handoff_failed(
            db,
            handoff["id"],
            str(exc),
        )

        raise

    return redirect(
        url_for(
            "katana_index",
            slug=slug,
        )
    )


# KATANA -> HTTPX


@app.route(
    "/p/<slug>/katana/run/<run_id>/send/httpx/",
    methods=[
        "POST",
    ],
)
def katana_send_to_httpx(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    if (
        get_katana_run(
            db,
            run_id,
        )
        is None
    ):
        abort(404)

    source_targets = collect_katana_targets(
        db,
        run_id,
    )

    if not source_targets:
        abort(
            400,
            ("This Katana run has no URLs to hand off."),
        )

    options = {
        "rate_limit": (
            integer_form_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=1000,
            )
        ),
        "redirect_depth": (
            integer_form_option(
                "redirect_depth",
                default=10,
                minimum=0,
                maximum=50,
            )
        ),
        "screenshots": (request.form.get("screenshots") == "1"),
    }

    handoff = create_handoff(
        db_path=db,
        project_root=project["root"],
        source_engine="katana",
        source_run_id=run_id,
        destination_engine="httpx",
        destination_profile="full",
        targets=source_targets,
        options=options,
    )

    payload = {
        **options,
        "target_count": (handoff["target_count"]),
        "source_handoff_id": (handoff["id"]),
        "source_engine": "katana",
        "source_run_id": run_id,
        "context": "anonymous",
    }

    try:
        job_id = launch_httpx_job(
            project,
            payload,
            target_file=handoff["target_file"],
        )

        attach_destination_job(
            db,
            handoff["id"],
            job_id,
        )

    except Exception as exc:
        mark_handoff_failed(
            db,
            handoff["id"],
            str(exc),
        )

        raise

    return redirect(
        url_for(
            "httpx_index",
            slug=slug,
        )
    )


# HTTPX -> NUCLEI


@app.route(
    "/p/<slug>/httpx/run/<run_id>/send/nuclei/",
    methods=[
        "POST",
    ],
)
def httpx_send_to_nuclei(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    if (
        get_httpx_run(
            db,
            run_id,
        )
        is None
    ):
        abort(404)

    source_targets = collect_httpx_targets(
        db,
        run_id,
    )

    if not source_targets:
        abort(
            400,
            ("This HTTPX run has no HTTP(S) URLs for Nuclei."),
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
        "template_source": template_source_form_option(),
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
            integer_form_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_form_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "bulk_size": (
            integer_form_option(
                "bulk_size",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "no_interactsh": (request.form.get("no_interactsh") == "1"),
        "allow_headless": (request.form.get("allow_headless") == "1"),
    }

    handoff = create_handoff(
        db_path=db,
        project_root=project["root"],
        source_engine="httpx",
        source_run_id=run_id,
        destination_engine="nuclei",
        destination_profile="web-safe",
        targets=source_targets,
        options=options,
    )

    payload = {
        **options,
        "target_count": (handoff["target_count"]),
        "source_handoff_id": (handoff["id"]),
        "source_engine": "httpx",
        "source_run_id": run_id,
        "context": "anonymous",
    }

    try:
        job_id = launch_nuclei_job(
            project,
            payload,
            target_file=handoff["target_file"],
        )

        attach_destination_job(
            db,
            handoff["id"],
            job_id,
        )

    except Exception as exc:
        mark_handoff_failed(
            db,
            handoff["id"],
            str(exc),
        )

        raise

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )


# KATANA -> NUCLEI


@app.route(
    "/p/<slug>/katana/run/<run_id>/send/nuclei/",
    methods=[
        "POST",
    ],
)
def katana_send_to_nuclei(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    if (
        get_katana_run(
            db,
            run_id,
        )
        is None
    ):
        abort(404)

    source_targets = collect_katana_targets(
        db,
        run_id,
    )

    if not source_targets:
        abort(
            400,
            ("This Katana run has no HTTP(S) URLs for Nuclei."),
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
        "template_source": template_source_form_option(),
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
            integer_form_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_form_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "bulk_size": (
            integer_form_option(
                "bulk_size",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "no_interactsh": (request.form.get("no_interactsh") == "1"),
        "allow_headless": (request.form.get("allow_headless") == "1"),
    }

    handoff = create_handoff(
        db_path=db,
        project_root=project["root"],
        source_engine="katana",
        source_run_id=run_id,
        destination_engine="nuclei",
        destination_profile="web-safe",
        targets=source_targets,
        options=options,
    )

    payload = {
        **options,
        "target_count": (handoff["target_count"]),
        "source_handoff_id": (handoff["id"]),
        "source_engine": "katana",
        "source_run_id": run_id,
        "context": "anonymous",
    }

    try:
        job_id = launch_nuclei_job(
            project,
            payload,
            target_file=handoff["target_file"],
        )

        attach_destination_job(
            db,
            handoff["id"],
            job_id,
        )

    except Exception as exc:
        mark_handoff_failed(
            db,
            handoff["id"],
            str(exc),
        )

        raise

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )


# NUCLEI


@app.route("/p/<slug>/nuclei/")
def nuclei_index(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    ensure_nuclei_schema(db)

    runs = list_nuclei_runs(db)

    latest = latest_nuclei_run(db)

    latest_stats = (
        get_nuclei_run_stats(
            db,
            latest["id"],
        )
        if latest
        else None
    )

    jobs = list_engine_jobs(
        db,
        "nuclei",
        limit=20,
    )

    for job in jobs:
        payload = parse_job_payload(job)

        job["target_count"] = payload.get(
            "target_count",
            0,
        )

        job["source_engine"] = payload.get("source_engine")

        job["source_run_id"] = payload.get("source_run_id")

        job["source_handoff_id"] = payload.get("source_handoff_id")

        job["findings"] = 0

        job["critical"] = 0

        job["high"] = 0

        if job.get("run_id"):
            stats = get_nuclei_run_stats(
                db,
                job["run_id"],
            )

            job["findings"] = stats["total"]

            job["critical"] = stats["critical"]

            job["high"] = stats["high"]

    return render_template(
        "nuclei.html",
        project=project,
        runs=runs,
        latest=latest,
        latest_stats=latest_stats,
        jobs=jobs,
    )


@app.route(
    "/p/<slug>/nuclei/new/",
    methods=[
        "POST",
    ],
)
def nuclei_new_scan(
    slug: str,
):

    project = get_project_or_404(slug)

    (
        targets,
        filename,
    ) = collect_uploaded_targets()

    severities = request.form.getlist("severity")

    if not severities:
        severities = [
            "info",
            "low",
            "medium",
            "high",
            "critical",
        ]

    payload = {
        "target_count": len(targets),
        "template_source": template_source_form_option(),
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
            integer_form_option(
                "rate_limit",
                default=10,
                minimum=1,
                maximum=500,
            )
        ),
        "concurrency": (
            integer_form_option(
                "concurrency",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "bulk_size": (
            integer_form_option(
                "bulk_size",
                default=5,
                minimum=1,
                maximum=50,
            )
        ),
        "no_interactsh": (request.form.get("no_interactsh") == "1"),
        "allow_headless": (request.form.get("allow_headless") == "1"),
        "context": "anonymous",
        "uploaded_file": (filename),
    }

    launch_nuclei_job(
        project,
        payload,
        targets=targets,
    )

    return redirect(
        url_for(
            "nuclei_index",
            slug=slug,
        )
    )


@app.route("/p/<slug>/nuclei/run/<run_id>/")
def nuclei_run(
    slug: str,
    run_id: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    run = get_nuclei_run(
        db,
        run_id,
    )

    if run is None:
        abort(404)

    try:
        page = int(
            request.args.get(
                "page",
                1,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        page = 1

    page = max(
        1,
        page,
    )

    per_page = 100

    total = count_run_findings(
        db,
        run_id,
    )

    pages = max(
        1,
        math.ceil(total / per_page),
    )

    page = min(
        page,
        pages,
    )

    return render_template(
        "nuclei_run.html",
        project=project,
        run=run,
        findings=list_run_findings(
            db,
            run_id,
            page=page,
            per_page=per_page,
        ),
        stats=get_nuclei_run_stats(
            db,
            run_id,
        ),
        page=page,
        pages=pages,
        total=total,
    )


@app.route("/p/<slug>/nuclei/status.json")
def nuclei_status(
    slug: str,
):

    project = get_project_or_404(slug)

    db = project["database"]

    output = []

    for job in list_engine_jobs(
        db,
        "nuclei",
        limit=20,
    ):
        payload = parse_job_payload(job)

        item = {
            "id": job["id"],
            "status": job["status"],
            "run_id": job["run_id"],
            "target_count": (
                payload.get(
                    "target_count",
                    0,
                )
            ),
            "source_engine": (payload.get("source_engine")),
            "source_run_id": (payload.get("source_run_id")),
            "source_handoff_id": (payload.get("source_handoff_id")),
            "findings": 0,
            "critical": 0,
            "high": 0,
        }

        if job.get("run_id"):
            stats = get_nuclei_run_stats(
                db,
                job["run_id"],
            )

            item["findings"] = stats["total"]

            item["critical"] = stats["critical"]

            item["high"] = stats["high"]

        output.append(item)

    return jsonify({"jobs": output})


@app.route("/health")
def health():

    return {
        "status": "ok",
        "application": ("Reconmancer"),
    }


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        debug=False,
    )

from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from reconmancer.core.findings_workspace import (
    add_manual_evidence,
    add_note,
    add_tag,
    attach_pin_to_finding,
    create_finding,
    ensure_findings_schema,
    evidence_path,
    get_finding,
    list_findings,
    list_pins,
    pin_source,
    remove_finding_source,
    remove_tag,
    set_finding_archived,
    snapshot_source_as_evidence,
    unpin_source,
    update_finding,
    workspace_counts,
)

from reconmancer.core.projects import (
    load_project,
)

from reconmancer.core.source_browser import (
    correlation_matrix,
    search_sources,
)


HOME = Path("/opt/reconmancer")


findings_blueprint = Blueprint(
    "findings_workspace",
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


def finding_or_404(
    project: dict,
    finding_id: str,
):

    finding = get_finding(
        project["database"],
        finding_id,
    )

    if finding is None:
        abort(404)

    return finding


def integer_query(
    name: str,
    default: int,
) -> int:

    try:
        return int(
            request.args.get(
                name,
                default,
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        return default


def truthy_query(
    name: str,
) -> bool:

    return request.args.get(name, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def safe_return_path(
    slug: str,
) -> str | None:

    value = request.form.get(
        "return_to",
        "",
    ).strip()

    prefix = f"/p/{slug}/findings/"

    if value and value.startswith(prefix) and not value.startswith("//"):
        return value

    return None


@findings_blueprint.route("/p/<slug>/findings/")
def findings_index(
    slug: str,
):

    project = project_or_404(slug)

    db = project["database"]

    ensure_findings_schema(db)

    page = max(
        1,
        integer_query(
            "page",
            1,
        ),
    )

    source_browser = search_sources(
        db,
        engine=request.args.get(
            "engine",
            "all",
        ),
        status=request.args.get(
            "status",
            "",
        ),
        interesting=truthy_query("interesting"),
        severity=request.args.get(
            "severity",
            "",
        ),
        context=request.args.get(
            "context",
            "all",
        ),
        host=request.args.get(
            "host",
            "",
        ),
        query=request.args.get(
            "q",
            "",
        ),
        template_id=request.args.get(
            "template_id",
            "",
        ),
        pinned_only=truthy_query("pinned"),
        page=page,
        per_page=75,
    )

    workspace = {
        "counts": workspace_counts(db),
        "findings": list_findings(db),
        "pins": list_pins(
            db,
            limit=200,
        ),
        "sources": (source_browser["items"]),
        "source_total": (source_browser["total"]),
        "page": (source_browser["page"]),
        "pages": (source_browser["pages"]),
        "per_page": (source_browser["per_page"]),
        "filters": (source_browser["filters"]),
        "correlations": (
            correlation_matrix(
                db,
                context=(source_browser["filters"]["context"]),
                limit=100,
            )
        ),
    }

    return render_template(
        "findings.html",
        project=project,
        workspace=workspace,
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@findings_blueprint.route(
    "/p/<slug>/findings/pin/",
    methods=[
        "POST",
    ],
)
def findings_pin(
    slug: str,
):

    project = project_or_404(slug)

    engine = (
        request.form.get(
            "engine",
            "",
        )
        .strip()
        .lower()
    )

    run_id = request.form.get(
        "run_id",
        "",
    ).strip()

    try:
        record_id = int(
            request.form.get(
                "record_id",
                "",
            )
        )

    except (
        TypeError,
        ValueError,
    ):
        abort(
            400,
            "Invalid source record ID.",
        )

    try:
        pin_source(
            project["database"],
            engine,
            run_id,
            record_id,
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.findings_index",
                slug=slug,
                error=str(exc),
            )
        )

    return_to = safe_return_path(slug)

    if return_to:
        return redirect(return_to)

    return redirect(
        url_for(
            "findings_workspace.findings_index",
            slug=slug,
            message="Source pinned.",
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/pin/<int:pin_id>/remove/",
    methods=[
        "POST",
    ],
)
def findings_unpin(
    slug: str,
    pin_id: int,
):

    project = project_or_404(slug)

    unpin_source(
        project["database"],
        pin_id,
    )

    return_to = safe_return_path(slug)

    if return_to:
        return redirect(return_to)

    return redirect(
        url_for(
            "findings_workspace.findings_index",
            slug=slug,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/new/",
    methods=[
        "POST",
    ],
)
def finding_create(
    slug: str,
):

    project = project_or_404(slug)

    pin_ids = []

    for value in request.form.getlist("pin_id"):
        try:
            pin_ids.append(int(value))

        except ValueError:
            continue

    try:
        finding_id = create_finding(
            project["database"],
            title=request.form.get(
                "title",
                "",
            ),
            severity=request.form.get(
                "severity",
                "info",
            ),
            status=request.form.get(
                "status",
                "draft",
            ),
            host=request.form.get(
                "host",
                "",
            ),
            url=request.form.get(
                "url",
                "",
            ),
            description=request.form.get(
                "description",
                "",
            ),
            reproduction=request.form.get(
                "reproduction",
                "",
            ),
            impact=request.form.get(
                "impact",
                "",
            ),
            remediation=request.form.get(
                "remediation",
                "",
            ),
            pin_ids=pin_ids,
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.findings_index",
                slug=slug,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route("/p/<slug>/findings/<finding_id>/")
def finding_detail(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    finding = finding_or_404(
        project,
        finding_id,
    )

    pins = list_pins(
        project["database"],
        limit=500,
    )

    attached = {
        (
            source["source_engine"],
            source["source_run_id"],
            int(source["source_record_id"]),
        )
        for source in finding["sources"]
    }

    available_pins = []

    for pin in pins:
        key = (
            pin["source_engine"],
            pin["source_run_id"],
            int(pin["source_record_id"]),
        )

        if key not in attached:
            available_pins.append(pin)

    return render_template(
        "finding_detail.html",
        project=project,
        finding=finding,
        available_pins=(available_pins),
        message=request.args.get("message"),
        error=request.args.get("error"),
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/save/",
    methods=[
        "POST",
    ],
)
def finding_save(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    finding_or_404(
        project,
        finding_id,
    )

    try:
        update_finding(
            project["database"],
            finding_id,
            title=request.form.get(
                "title",
                "",
            ),
            severity=request.form.get(
                "severity",
                "info",
            ),
            status=request.form.get(
                "status",
                "draft",
            ),
            host=request.form.get(
                "host",
                "",
            ),
            url=request.form.get(
                "url",
                "",
            ),
            description=request.form.get(
                "description",
                "",
            ),
            reproduction=request.form.get(
                "reproduction",
                "",
            ),
            impact=request.form.get(
                "impact",
                "",
            ),
            remediation=request.form.get(
                "remediation",
                "",
            ),
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
            message="Finding saved.",
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/note/",
    methods=[
        "POST",
    ],
)
def finding_note(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    finding_or_404(
        project,
        finding_id,
    )

    try:
        add_note(
            project["database"],
            finding_id,
            request.form.get(
                "body",
                "",
            ),
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/tag/",
    methods=[
        "POST",
    ],
)
def finding_tag(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    finding_or_404(
        project,
        finding_id,
    )

    try:
        add_tag(
            project["database"],
            finding_id,
            request.form.get(
                "tag",
                "",
            ),
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/tag/remove/",
    methods=[
        "POST",
    ],
)
def finding_tag_remove(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    remove_tag(
        project["database"],
        finding_id,
        request.form.get(
            "tag",
            "",
        ),
    )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/source/add/",
    methods=[
        "POST",
    ],
)
def finding_source_add(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    try:
        pin_id = int(
            request.form.get(
                "pin_id",
                "",
            )
        )

        attach_pin_to_finding(
            project["database"],
            finding_id,
            pin_id,
        )

    except (
        ValueError,
        TypeError,
    ) as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/source/<int:source_id>/remove/",
    methods=[
        "POST",
    ],
)
def finding_source_remove(
    slug: str,
    finding_id: str,
    source_id: int,
):

    project = project_or_404(slug)

    remove_finding_source(
        project["database"],
        finding_id,
        source_id,
    )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/source/<int:source_id>/snapshot/",
    methods=[
        "POST",
    ],
)
def finding_source_snapshot(
    slug: str,
    finding_id: str,
    source_id: int,
):

    project = project_or_404(slug)

    try:
        evidence_hash = snapshot_source_as_evidence(
            project["database"],
            project["root"],
            finding_id,
            source_id,
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
            message=("Evidence snapshot saved: " + evidence_hash[:12] + "…"),
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/evidence/manual/",
    methods=[
        "POST",
    ],
)
def finding_manual_evidence(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    try:
        add_manual_evidence(
            project["database"],
            project["root"],
            finding_id,
            label=request.form.get(
                "label",
                "",
            ),
            body=request.form.get(
                "body",
                "",
            ),
        )

    except ValueError as exc:
        return redirect(
            url_for(
                "findings_workspace.finding_detail",
                slug=slug,
                finding_id=finding_id,
                error=str(exc),
            )
        )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
            message="Evidence saved.",
        )
    )


@findings_blueprint.route("/p/<slug>/findings/<finding_id>/evidence/<int:evidence_id>/")
def finding_evidence_download(
    slug: str,
    finding_id: str,
    evidence_id: int,
):

    project = project_or_404(slug)

    finding = finding_or_404(
        project,
        finding_id,
    )

    path = evidence_path(
        project["root"],
        finding,
        evidence_id,
    )

    if path is None:
        abort(404)

    return send_file(
        path,
        conditional=True,
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/archive/",
    methods=[
        "POST",
    ],
)
def finding_archive(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    set_finding_archived(
        project["database"],
        finding_id,
        True,
    )

    return redirect(
        url_for(
            "findings_workspace.findings_index",
            slug=slug,
            message=(f"{finding_id} archived."),
        )
    )


@findings_blueprint.route(
    "/p/<slug>/findings/<finding_id>/restore/",
    methods=[
        "POST",
    ],
)
def finding_restore(
    slug: str,
    finding_id: str,
):

    project = project_or_404(slug)

    set_finding_archived(
        project["database"],
        finding_id,
        False,
    )

    return redirect(
        url_for(
            "findings_workspace.finding_detail",
            slug=slug,
            finding_id=finding_id,
        )
    )

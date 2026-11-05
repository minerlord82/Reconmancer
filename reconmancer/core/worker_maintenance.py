from __future__ import annotations

from reconmancer.core.analysis import refresh_url_analysis
from reconmancer.core.compression import maybe_run_compression


def post_scan_maintenance(project: dict, *, current_job_id: str | None = None) -> dict:
    output = {"analysis": None, "compression": None, "errors": []}
    try:
        output["analysis"] = refresh_url_analysis(project["database"])
    except Exception as exc:
        output["errors"].append(f"analysis: {exc}")

    excludes = set()
    if current_job_id:
        excludes.add(project["root"] / "logs" / "jobs" / f"{current_job_id}.log")

    try:
        output["compression"] = maybe_run_compression(
            project,
            exclude_paths=excludes,
        )
    except Exception as exc:
        output["errors"].append(f"compression: {exc}")
    return output

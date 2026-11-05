from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from reconmancer.core.database import connect
from reconmancer.core.handoffs import ensure_handoff_schema


DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def parse_json_object(
    value: str | None,
) -> dict:

    if not value:
        return {}

    try:
        parsed = json.loads(value)

    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return {}

    if not isinstance(
        parsed,
        dict,
    ):
        return {}

    return parsed


def parse_datetime(
    value: str | None,
) -> datetime | None:

    if not value:
        return None

    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        return datetime.fromisoformat(value)

    except (
        TypeError,
        ValueError,
    ):
        return None


def timestamp_value(
    value: str | None,
) -> float:

    parsed = parse_datetime(value)

    if parsed is None:
        return 0.0

    try:
        return parsed.timestamp()

    except (
        ValueError,
        OSError,
    ):
        return 0.0


def duration_seconds(
    started_at: str | None,
    finished_at: str | None,
) -> float | None:

    started = parse_datetime(started_at)

    finished = parse_datetime(finished_at)

    if started is None or finished is None:
        return None

    value = (finished - started).total_seconds()

    return max(
        0.0,
        value,
    )


def duration_label(
    seconds: float | None,
) -> str:

    if seconds is None:
        return "—"

    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"

    if seconds < 60:
        return f"{seconds:.1f} s"

    minutes = int(seconds // 60)

    remaining_seconds = int(seconds % 60)

    if minutes < 60:
        return f"{minutes}m {remaining_seconds}s"

    hours = int(minutes // 60)

    remaining_minutes = int(minutes % 60)

    return f"{hours}h {remaining_minutes}m"


def get_runs(
    db_path: Path,
    *,
    limit: int,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                engine,
                profile,
                context,
                status,

                started_at,
                finished_at,

                input_count,
                result_count,

                command_json,
                error

            FROM runs

            ORDER BY
                started_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_jobs(
    db_path: Path,
    *,
    limit: int,
) -> list[dict]:

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                engine,
                status,

                created_at,
                started_at,
                finished_at,

                payload_json,
                run_id

            FROM jobs

            ORDER BY
                created_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        output = []

        for row in rows:
            item = dict(row)

            item["payload"] = parse_json_object(item.get("payload_json"))

            output.append(item)

        return output

    finally:
        connection.close()


def get_handoffs(
    db_path: Path,
    *,
    limit: int,
) -> list[dict]:

    ensure_handoff_schema(db_path)

    connection = connect(db_path)

    try:
        rows = connection.execute(
            """
            SELECT
                q.id,

                q.source_engine,
                q.source_run_id,

                q.destination_engine,
                q.destination_profile,

                q.status
                    AS handoff_status,

                q.target_count,

                q.destination_job_id,

                q.created_at,
                q.launched_at,

                q.error,

                j.status
                    AS job_status,

                j.run_id
                    AS destination_run_id

            FROM handoff_queue q

            LEFT JOIN jobs j
              ON j.id =
                 q.destination_job_id

            ORDER BY
                q.created_at DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        output = []

        for row in rows:
            item = dict(row)

            item["effective_status"] = (
                item.get("job_status") or item.get("handoff_status") or "unknown"
            )

            output.append(item)

        return output

    finally:
        connection.close()


def build_runs_workspace(
    db_path: Path,
    *,
    limit: int = DEFAULT_LIMIT,
) -> dict:

    limit = max(
        1,
        min(
            int(limit),
            MAX_LIMIT,
        ),
    )

    runs = get_runs(
        db_path,
        limit=limit,
    )

    jobs = get_jobs(
        db_path,
        limit=limit,
    )

    handoffs = get_handoffs(
        db_path,
        limit=limit,
    )

    jobs_by_run = {}

    for job in jobs:
        run_id = job.get("run_id")

        if not run_id:
            continue

        jobs_by_run.setdefault(
            run_id,
            job,
        )

    handoffs_by_id = {item["id"]: item for item in handoffs}

    downstream_by_run = {}

    for handoff in handoffs:
        source_run_id = handoff.get("source_run_id")

        if not source_run_id:
            continue

        downstream_by_run.setdefault(
            source_run_id,
            [],
        ).append(handoff)

    for run in runs:
        seconds = duration_seconds(
            run.get("started_at"),
            run.get("finished_at"),
        )

        run["duration_seconds"] = seconds

        run["duration"] = duration_label(seconds)

        job = jobs_by_run.get(run["id"])

        run["job"] = job

        run["source_handoff"] = None

        run["source_engine"] = None

        run["source_run_id"] = None

        if job:
            payload = job.get(
                "payload",
                {},
            )

            source_handoff_id = payload.get("source_handoff_id")

            run["source_engine"] = payload.get("source_engine")

            run["source_run_id"] = payload.get("source_run_id")

            if source_handoff_id:
                run["source_handoff"] = handoffs_by_id.get(source_handoff_id)

        run["downstream_handoffs"] = downstream_by_run.get(
            run["id"],
            [],
        )

    for job in jobs:
        seconds = duration_seconds(
            job.get("started_at"),
            job.get("finished_at"),
        )

        job["duration_seconds"] = seconds

        job["duration"] = duration_label(seconds)

        job["target_count"] = job.get(
            "payload",
            {},
        ).get(
            "target_count",
            0,
        )

    timeline = []

    for run in runs:
        timeline.append(
            {
                "kind": "run",
                "time": (run.get("started_at")),
                "sort_time": timestamp_value(run.get("started_at")),
                "id": run["id"],
                "engine": run["engine"],
                "status": run["status"],
                "profile": run.get("profile"),
                "input_count": (run.get("input_count") or 0),
                "result_count": (run.get("result_count") or 0),
                "duration": run["duration"],
                "error": run.get("error"),
                "run_id": run["id"],
                "source_engine": (run.get("source_engine")),
                "source_run_id": (run.get("source_run_id")),
                "destination_engine": None,
                "destination_run_id": None,
            }
        )

    for job in jobs:
        payload = job.get(
            "payload",
            {},
        )

        timeline.append(
            {
                "kind": "job",
                "time": job.get("created_at"),
                "sort_time": timestamp_value(job.get("created_at")),
                "id": job["id"],
                "engine": job["engine"],
                "status": job["status"],
                "profile": payload.get("profile"),
                "input_count": (job.get("target_count") or 0),
                "result_count": None,
                "duration": job["duration"],
                "error": None,
                "run_id": job.get("run_id"),
                "source_engine": (payload.get("source_engine")),
                "source_run_id": (payload.get("source_run_id")),
                "destination_engine": (job["engine"]),
                "destination_run_id": (job.get("run_id")),
            }
        )

    for handoff in handoffs:
        timeline.append(
            {
                "kind": "handoff",
                "time": handoff.get("created_at"),
                "sort_time": timestamp_value(handoff.get("created_at")),
                "id": handoff["id"],
                "engine": None,
                "status": handoff["effective_status"],
                "profile": handoff.get("destination_profile"),
                "input_count": (handoff.get("target_count") or 0),
                "result_count": None,
                "duration": "—",
                "error": handoff.get("error"),
                "run_id": None,
                "source_engine": (handoff.get("source_engine")),
                "source_run_id": (handoff.get("source_run_id")),
                "destination_engine": (handoff.get("destination_engine")),
                "destination_run_id": (handoff.get("destination_run_id")),
                "destination_job_id": (handoff.get("destination_job_id")),
            }
        )

    timeline.sort(
        key=lambda item: item["sort_time"],
        reverse=True,
    )

    timeline = timeline[:limit]

    counts = {
        "runs": len(runs),
        "jobs": len(jobs),
        "handoffs": len(handoffs),
        "failed_runs": sum(1 for run in runs if run.get("status") == "failed"),
        "active_jobs": sum(
            1
            for job in jobs
            if job.get("status")
            in {
                "queued",
                "running",
            }
        ),
    }

    return {
        "runs": runs,
        "jobs": jobs,
        "handoffs": handoffs,
        "timeline": timeline,
        "counts": counts,
    }

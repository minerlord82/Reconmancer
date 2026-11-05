from __future__ import annotations

import re
import shutil
from pathlib import Path

from reconmancer.core.analysis import ensure_analysis_schema
from reconmancer.core.database import connect, initialize_database
from reconmancer.core.findings_workspace import ensure_findings_schema
from reconmancer.core.handoffs import ensure_handoff_schema
from reconmancer.core.jobs import ensure_job_schema
from reconmancer.core.projects import directory_size, load_project, project_path
from reconmancer.core.traffic_evidence import ensure_traffic_evidence_schema
from reconmancer.engines.katana.schema import ensure_katana_schema
from reconmancer.engines.nuclei.schema import ensure_nuclei_schema


ACTIVE_JOB_STATUSES = {
    "queued",
    "running",
    "stale",
}


RUNTIME_DIRECTORIES = (
    "raw/httpx",
    "raw/katana",
    "raw/nuclei",
    "objects/screenshots",
    "objects/thumbnails",
    "objects/responses",
    "objects/evidence",
    "input/jobs",
    "input/handoffs",
    "logs",
    "temp",
)


COLLECTED_ROOTS = (
    "raw",
    "objects",
    "input/jobs",
    "input/handoffs",
    "logs",
    "temp",
)


SLUG_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def suggested_slug(name: str) -> str:
    value = SLUG_NON_ALNUM.sub(
        "-",
        name.strip().lower(),
    ).strip("-")

    return value[:64]


def ensure_runtime_directories(project_root: Path) -> None:
    for relative in RUNTIME_DIRECTORIES:
        (project_root / relative).mkdir(
            parents=True,
            exist_ok=True,
        )

    targets = project_root / "input" / "targets.txt"
    targets.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    targets.touch(exist_ok=True)

    auth_root = project_root / "secrets" / "auth"
    auth_root.mkdir(
        parents=True,
        exist_ok=True,
    )


def initialize_full_project_schema(db_path: Path) -> None:
    initialize_database(db_path)
    ensure_job_schema(db_path)
    ensure_katana_schema(db_path)
    ensure_nuclei_schema(db_path)
    ensure_handoff_schema(db_path)
    ensure_findings_schema(db_path)
    ensure_traffic_evidence_schema(db_path)
    ensure_analysis_schema(db_path)


def active_jobs(db_path: Path) -> list[dict]:
    if not db_path.is_file():
        return []

    ensure_job_schema(db_path)

    connection = connect(db_path)

    try:
        placeholders = ",".join("?" for _ in ACTIVE_JOB_STATUSES)

        rows = connection.execute(
            f"""
            SELECT
                id,
                engine,
                status,
                worker_pid,
                created_at,
                started_at

            FROM jobs

            WHERE status IN ({placeholders})

            ORDER BY created_at ASC
            """,
            tuple(sorted(ACTIVE_JOB_STATUSES)),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def _remove_database_files(db_path: Path) -> None:
    if db_path.is_file():
        try:
            connection = connect(db_path)

            try:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()

        except Exception:
            # The wipe still proceeds after active-job protection. A stale
            # checkpoint must not leave the old project data behind.
            pass

    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(db_path) + suffix)

        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def wipe_collected_data(project: dict) -> dict:
    root = Path(project["root"])
    db_path = Path(project["database"])

    running = active_jobs(db_path)

    if running:
        details = ", ".join(f"{item['id']} ({item['status']})" for item in running[:8])

        if len(running) > 8:
            details += ", ..."

        raise ValueError(
            "Project wipe refused because active jobs still exist: " + details
        )

    before_bytes = directory_size(root)

    _remove_database_files(db_path)

    for relative in COLLECTED_ROOTS:
        path = root / relative

        if not path.exists():
            continue

        if path.is_dir():
            shutil.rmtree(
                path,
                ignore_errors=True,
            )
        else:
            path.unlink(missing_ok=True)

    ensure_runtime_directories(root)
    initialize_full_project_schema(db_path)

    after_bytes = directory_size(root)

    return {
        "before_bytes": before_bytes,
        "after_bytes": after_bytes,
        "removed_bytes": max(
            0,
            before_bytes - after_bytes,
        ),
        "preserved": [
            "project.yaml and project settings",
            "input/targets.txt",
            "secrets/auth authentication profiles",
        ],
    }


def delete_project(home: Path, slug: str) -> dict:
    project = load_project(
        home,
        slug,
    )

    root = Path(project["root"])
    db_path = Path(project["database"])

    running = active_jobs(db_path)

    if running:
        raise ValueError("Project deletion refused while queued/running jobs exist.")

    projects_root = (home / "projects").resolve()
    root_resolved = root.resolve()

    if root_resolved.parent != projects_root:
        raise ValueError("Project path failed safety validation.")

    removed_bytes = directory_size(root_resolved)

    shutil.rmtree(
        root_resolved,
    )

    return {
        "slug": slug,
        "removed_bytes": removed_bytes,
    }


def prepare_new_project(home: Path, slug: str) -> dict:
    project = load_project(
        home,
        slug,
    )

    ensure_runtime_directories(Path(project["root"]))

    initialize_full_project_schema(Path(project["database"]))

    return project
